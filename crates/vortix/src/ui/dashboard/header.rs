use crate::app::App;
use crate::state::QualityLevel;
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::engine::TunnelSnapshot;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthStr;

/// Render the header bar from the registry's three states (U16 of plan #001).
///
/// Branches:
/// * `tunnel_count == 0` → `⚠ Real: <public_ip>` warning form (no VPN; real
///   IP exposed). Replaces the legacy `○ DISCONNECTED ... Your IP:` row.
/// * `tunnel_count >= 1` and a primary is elected → today's single-tunnel
///   rendering (CONNECTING / CONNECTED / etc.) sourced from
///   `registry.snapshot(primary)` and `app.runtime` telemetry. When
///   `tunnel_count >= 2`, a `Tunnels [ ... ]` strip is appended after the
///   primary segment with an overflow ladder for narrow widths.
/// * `tunnel_count >= 1` and no primary (e.g., only addressable secondaries
///   connected, kernel default route held elsewhere) → warning form +
///   tunnels strip.
///
/// Density via signaling: the strip only appears when N >= 2; a lone tunnel
/// keeps the existing single-line shape. When the strip cannot fit at the
/// current width, names are abbreviated to the first character, then
/// dropped with a `+N` overflow suffix, then the whole strip collapses to a
/// dot-row of badge chars (`[●●●● +1]`).
#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &App, area: Rect) {
    let tunnel_count = app.registry.tunnel_count();
    let primary = app.registry.primary().cloned();
    let primary_snap = primary.as_ref().and_then(|id| app.registry.snapshot(id));

    let ks_indicator = get_killswitch_indicator(app);

    // ── 0-active branch: no tunnels in the registry → real IPv4 exposed.
    // Show the explicit `○ DISCONNECTED` title here — the user's
    // mental model is "no VPN at all" and the title makes that
    // unambiguous. The no-primary-but-tunnels-up branch below still
    // uses the `⚠ Real:` form because saying DISCONNECTED there
    // would be a lie (tunnels ARE up, just split-route only).
    if tunnel_count == 0 {
        let line = render_disconnected_line(app, ks_indicator.clone());
        frame.render_widget(Paragraph::new(line), area);
        return;
    }

    // ── ≥1-active branch with no elected primary: tunnels are up but
    // the kernel default route isn't theirs (split-only topology, or
    // an externally-adopted unauthoritative tunnel). Surface the
    // explicit `○ NO EXIT` title — different from DISCONNECTED
    // (tunnels ARE up) and from CONNECTED (no exit owner). Tunnels
    // strip still appends so the user sees what's connected.
    let Some(primary_snap) = primary_snap else {
        let snapshots = app.registry.snapshot_all();
        let mut line = render_no_exit_line(app, ks_indicator.clone());
        line = append_tunnels_strip(line, &snapshots, primary.as_ref(), area.width);
        frame.render_widget(Paragraph::new(line), area);
        return;
    };

    // ── Primary present: today's single-tunnel rendering, optionally with
    // the tunnels strip when N >= 2.
    let mut line = render_primary_line(app, &primary_snap, ks_indicator, area.width);

    if tunnel_count >= 2 {
        let snapshots = app.registry.snapshot_all();
        line = append_tunnels_strip(line, &snapshots, primary.as_ref(), area.width);
    }

    frame.render_widget(Paragraph::new(line), area);
}

/// Build the `○ NO EXIT │ Real: <public_ip>` header used when ≥1
/// tunnel is in the registry but the kernel default route isn't
/// theirs (split-only topology, or an externally-adopted
/// unauthoritative tunnel). Distinguishes from
/// [`render_disconnected_line`] (genuine no-VPN) and from the
/// CONNECTED primary line. Vocabulary matches Security Guard's
/// "split-route — no exit" copy.
fn render_no_exit_line(app: &App, ks_indicator: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            "\u{25cb} NO EXIT",
            Style::default()
                .fg(theme::WARNING)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled("Real: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            app.runtime.public_ip.clone(),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        ks_indicator,
    ])
}

/// Build the `○ DISCONNECTED │ Real: <public_ip>` header used when the
/// registry holds zero tunnels — a genuine no-VPN state. The explicit
/// title was removed by the U16 redesign in favour of the `⚠ Real:`
/// form alone; that conflated "no exit selected" with "no VPN at all"
/// from the user's perspective, so the title is back. The killswitch
/// indicator still appends.
fn render_disconnected_line(app: &App, ks_indicator: Span<'static>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            "\u{25cb} DISCONNECTED",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        Span::styled("Real: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            app.runtime.public_ip.clone(),
            Style::default().fg(theme::TEXT_PRIMARY),
        ),
        Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
        ks_indicator,
    ])
}

/// Render the primary-tunnel section (CONNECTING / CONNECTED / etc.). This
/// is the existing single-tunnel rendering preserved verbatim from U6B; the
/// only behavioural delta is that the `(+N more)` suffix has been retired
/// in favour of the explicit Tunnels strip appended by the caller.
#[allow(clippy::too_many_lines)]
fn render_primary_line(
    app: &App,
    primary_snap: &TunnelSnapshot,
    ks_indicator: Span<'static>,
    area_width: u16,
) -> Line<'static> {
    match &primary_snap.state {
        Connection::Disconnected { .. } => {
            // count >= 1 with a primary snapshot but state==Disconnected
            // is a transient window (registry entry survives a brief
            // disconnect for journal purposes). Use the NO EXIT title —
            // the registry has tunnels but the primary slot isn't
            // serving as exit right now.
            render_no_exit_line(app, ks_indicator)
        }
        Connection::Connecting { started_at, .. }
        | Connection::Disconnecting { started_at, .. }
        | Connection::Reconnecting { started_at, .. } => {
            let profile_name = primary_snap.profile_id.as_str();
            let elapsed = started_at.elapsed().map_or(0, |d| d.as_secs());
            let spinner_frames = ['◐', '◓', '◑', '◒'];
            #[allow(clippy::cast_possible_truncation)]
            let spinner = spinner_frames[(elapsed as usize) % spinner_frames.len()];
            let action = match primary_snap.state {
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
        Connection::AwaitingUserInput { .. } => Line::from(vec![
            Span::styled(
                "? AWAITING INPUT",
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" │", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
            ks_indicator,
        ]),
        Connection::Connected { details, since, .. } => {
            let profile_name = primary_snap.profile_id.as_str();

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
                Span::styled(" │ ", Style::default().fg(theme::NORD_POLAR_NIGHT_4)),
                Span::styled("VPN: ", Style::default().fg(theme::TEXT_SECONDARY)),
                Span::styled(
                    app.runtime.public_ip.clone(),
                    Style::default().fg(theme::SUCCESS),
                ),
            ];

            if !app.runtime.location.is_empty()
                && app.runtime.location != "Unknown"
                && app.runtime.location != constants::MSG_DETECTING
            {
                let loc_budget = (area_width as usize / 4).max(10);
                header_spans.push(Span::styled(
                    " @ ",
                    Style::default().fg(theme::TEXT_SECONDARY),
                ));
                header_spans.push(Span::styled(
                    utils::truncate(&app.runtime.location, loc_budget),
                    Style::default().fg(theme::ACCENT_PRIMARY),
                ));
            }

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
    }
}

/// Per-state badge char + colour used in the tunnels strip. Mirrors the
/// sidebar's badge mapping so cross-surface signal stays consistent.
/// `Disconnected` snapshots are filtered out by the caller — when a tunnel
/// is registered but truly disconnected, it doesn't belong on the strip.
fn strip_badge(state: &Connection) -> Option<(&'static str, Color)> {
    match state {
        Connection::Connected { .. } => Some(("●", theme::SUCCESS)),
        Connection::Connecting { .. } => Some(("…", theme::WARNING)),
        Connection::Reconnecting { .. } => Some(("↻", theme::WARNING)),
        Connection::Disconnecting { .. } => Some(("⏻", theme::WARNING)),
        Connection::AwaitingUserInput { .. } => Some(("?", theme::WARNING)),
        Connection::Disconnected { .. } => None,
    }
}

/// Compute the rendered display width (in terminal cells) of a `Line`.
fn line_display_width(line: &Line<'_>) -> usize {
    line.spans.iter().map(|s| s.content.width()).sum()
}

/// Append the `Tunnels: [ … ]` strip onto an existing header line. Picks
/// progressively denser forms based on how much horizontal budget remains:
///
/// 1. **Wide**: `│ Tunnels: [●corp ●lab ↻home]` — full names with per-tunnel
///    badge chars.
/// 2. **Narrow**: `│ Tunnels: [●c ●l +1]` — names abbreviated to a single
///    char; overflow tail tracks tunnels that didn't fit.
/// 3. **Very narrow**: `│ [●●●● +2]` — pure dot-row of badges, drops the
///    `Tunnels:` label.
/// 4. **Pathological**: the strip is dropped entirely; the existing header
///    line stays untouched so callers always get a renderable result.
///
/// The primary is rendered first in stable order so the user always sees
/// "which tunnel owns the default route" at position 0.
fn append_tunnels_strip(
    mut line: Line<'static>,
    snapshots: &[TunnelSnapshot],
    primary: Option<&crate::vortix_core::profile::ProfileId>,
    area_width: u16,
) -> Line<'static> {
    // Order: primary first (if any), then remaining stable-sorted.
    let mut ordered: Vec<&TunnelSnapshot> = Vec::with_capacity(snapshots.len());
    if let Some(p) = primary {
        if let Some(s) = snapshots.iter().find(|s| &s.profile_id == p) {
            ordered.push(s);
        }
    }
    for s in snapshots {
        if Some(&s.profile_id) != primary {
            ordered.push(s);
        }
    }

    // Filter out Disconnected entries — they're registered but inactive.
    let visible: Vec<(&TunnelSnapshot, &'static str, Color)> = ordered
        .iter()
        .filter_map(|s| strip_badge(&s.state).map(|(g, c)| (*s, g, c)))
        .collect();

    if visible.is_empty() {
        return line;
    }

    let used = line_display_width(&line);
    let budget = (area_width as usize).saturating_sub(used);
    // Need at minimum `│ [●] ` ≈ 6 cells before bothering.
    if budget < 8 {
        return line;
    }

    let separator = " │ ";
    let sep_w = separator.width();

    // ── Tier 1: full names.
    let full_inner = build_strip_inner(&visible);
    let full_w = sep_w + "Tunnels: [".width() + full_inner.0 + "]".width();
    if full_w <= budget {
        push_strip(&mut line, /* label */ true, &full_inner.1);
        return line;
    }

    // ── Tier 2: 1-char names + `+N` overflow tail.
    if let Some(narrow) = build_narrow_strip(
        &visible,
        budget.saturating_sub(sep_w + "Tunnels: [".width() + "]".width()),
    ) {
        push_strip(&mut line, /* label */ true, &narrow);
        return line;
    }

    // ── Tier 3: dot-row, no `Tunnels:` label.
    if let Some(dots) = build_dotrow(
        &visible,
        budget.saturating_sub(sep_w + "[".width() + "]".width()),
    ) {
        push_strip(&mut line, /* label */ false, &dots);
        return line;
    }

    line
}

/// Tier-1 builder: full names, no overflow. Returns total display width
/// plus the rendered spans. Caller checks whether the result fits before
/// committing to this density.
fn build_strip_inner(
    visible: &[(&TunnelSnapshot, &'static str, Color)],
) -> (usize, Vec<Span<'static>>) {
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(visible.len() * 3);
    let mut width = 0usize;
    for (idx, (snap, badge, color)) in visible.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled(
                " ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ));
            width += 1;
        }
        spans.push(Span::styled(
            (*badge).to_string(),
            Style::default().fg(*color),
        ));
        width += badge.width();
        let name = snap.profile_id.as_str().to_string();
        if !name.is_empty() {
            width += name.width();
            spans.push(Span::styled(name, Style::default().fg(theme::TEXT_PRIMARY)));
        }
    }
    (width, spans)
}

/// Tier-2 builder: 1-char names, dropping tunnels off the end to fit and
/// summarising the drop as ` +N`.
fn build_narrow_strip(
    visible: &[(&TunnelSnapshot, &'static str, Color)],
    inner_budget: usize,
) -> Option<Vec<Span<'static>>> {
    // Greedy fit: include as many tunnels as possible at 1-char-name density.
    // Reserve room for a `+N` tail when not everything fits.
    let total = visible.len();
    let mut shown = 0usize;
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(total * 3);
    let mut width = 0usize;

    for (idx, (snap, badge, color)) in visible.iter().enumerate() {
        // Cost of this tunnel: optional separator + badge + 1-char name.
        let name = snap.profile_id.as_str();
        let first_char: String = name.chars().take(1).collect();
        let sep_cost = usize::from(idx != 0);
        let cost = sep_cost + badge.width() + first_char.width();

        // Reserve overflow tail when there are still more tunnels behind us.
        let remaining_after = total - idx - 1;
        let tail_reserve = if remaining_after > 0 {
            format!(" +{remaining_after}").width()
        } else {
            0
        };

        if width + cost + tail_reserve > inner_budget {
            break;
        }

        if idx > 0 {
            spans.push(Span::styled(
                " ",
                Style::default().fg(theme::TEXT_SECONDARY),
            ));
        }
        spans.push(Span::styled(
            (*badge).to_string(),
            Style::default().fg(*color),
        ));
        if !first_char.is_empty() {
            spans.push(Span::styled(
                first_char,
                Style::default().fg(theme::TEXT_PRIMARY),
            ));
        }
        width += cost;
        shown += 1;
    }

    if shown == 0 {
        return None;
    }

    let omitted = total - shown;
    if omitted > 0 {
        spans.push(Span::styled(
            format!(" +{omitted}"),
            Style::default().fg(theme::TEXT_SECONDARY),
        ));
    }
    Some(spans)
}

/// Tier-3 builder: badges only (no names), dropping tunnels off the end to
/// fit. Primary stays at position 0 because `visible` is already primary-
/// first ordered.
fn build_dotrow(
    visible: &[(&TunnelSnapshot, &'static str, Color)],
    inner_budget: usize,
) -> Option<Vec<Span<'static>>> {
    let total = visible.len();
    let mut shown = 0usize;
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(total);
    let mut width = 0usize;

    for (idx, (_snap, badge, color)) in visible.iter().enumerate() {
        let remaining_after = total - idx - 1;
        let tail_reserve = if remaining_after > 0 {
            format!(" +{remaining_after}").width()
        } else {
            0
        };
        let cost = badge.width();
        if width + cost + tail_reserve > inner_budget {
            break;
        }
        spans.push(Span::styled(
            (*badge).to_string(),
            Style::default().fg(*color),
        ));
        width += cost;
        shown += 1;
    }

    if shown == 0 {
        return None;
    }

    let omitted = total - shown;
    if omitted > 0 {
        spans.push(Span::styled(
            format!(" +{omitted}"),
            Style::default().fg(theme::TEXT_SECONDARY),
        ));
    }
    Some(spans)
}

/// Push the assembled strip spans onto the trailing edge of the header line.
fn push_strip(line: &mut Line<'static>, with_label: bool, inner: &[Span<'static>]) {
    line.spans.push(Span::styled(
        " │ ",
        Style::default().fg(theme::NORD_POLAR_NIGHT_4),
    ));
    if with_label {
        line.spans.push(Span::styled(
            "Tunnels: ",
            Style::default().fg(theme::TEXT_SECONDARY),
        ));
    }
    line.spans.push(Span::styled(
        "[",
        Style::default().fg(theme::TEXT_SECONDARY),
    ));
    for s in inner {
        line.spans.push(s.clone());
    }
    line.spans.push(Span::styled(
        "]",
        Style::default().fg(theme::TEXT_SECONDARY),
    ));
}

/// Kill switch indicator for the header bar.
///
/// Header labels (kept short for the top strip):
/// - `KS:Off` — no firewall rules (mode `Off`)
/// - `KS:Watch` — `Auto` + `Armed`; watching the VPN (green / healthy)
/// - `KS:VPN-only` — `AlwaysOn` + `Blocking`; steady state (green / working as configured, NOT an alarm)
/// - `KS:DROPPED` — `Auto` + `Blocking`; VPN actually dropped, firewall engaged (red / alarm)
///
/// The variant names `Off` / `Auto` / `AlwaysOn` are the stable
/// CLI/JSON contract — never renamed. The labels here are the UI
/// vocabulary; see `vortix_core::state::killswitch` module docs for
/// the mapping convention.
fn get_killswitch_indicator(app: &App) -> Span<'static> {
    use crate::state::{KillSwitchMode, KillSwitchState};

    match (app.runtime.killswitch_mode, app.runtime.killswitch_state) {
        (KillSwitchMode::Off, _) | (_, KillSwitchState::Disabled) => {
            Span::styled(" KS:Off ", Style::default().fg(theme::INACTIVE))
        }
        // AlwaysOn + Blocking is the steady state for VPN-only mode —
        // green/by-design, not an alarm. Caught before the generic
        // `(_, Blocking)` arm so it doesn't get the red alarm treatment.
        (KillSwitchMode::AlwaysOn, _) => {
            Span::styled(" KS:VPN-only ", Style::default().fg(theme::SUCCESS))
        }
        // Auto + Blocking means the VPN actually dropped and the
        // firewall engaged in response — that IS the alarm condition.
        (_, KillSwitchState::Blocking) => Span::styled(
            " KS:DROPPED ",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ),
        (KillSwitchMode::Auto, KillSwitchState::Armed) => {
            Span::styled(" KS:Watch ", Style::default().fg(theme::SUCCESS))
        }
    }
}

#[cfg(test)]
mod tests {
    //! U16 header rendering tests. These exercise the empty-registry and
    //! `≥2` overflow ladder paths via `App::new_test` + direct construction
    //! of `TunnelSnapshot` values fed to the strip builders. The strip
    //! builders are deliberately the unit-of-test rather than the full
    //! `render()` path because populating a real `TunnelRegistry<TunnelKind>`
    //! requires driving the FSM through async tunnel ops — out of scope for
    //! the rendering smoke covered here.
    use super::*;
    use crate::app::App;
    use crate::vortix_core::engine::state::{Connection, ConnectionHealth, DetailedConnectionInfo};
    use crate::vortix_core::engine::{Role, TunnelSnapshot};
    use crate::vortix_core::profile::ProfileId;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::Terminal;
    use std::time::SystemTime;

    fn snap(name: &str, state: Connection) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: ProfileId::new(name),
            state,
            role: Role::Addressable {
                allowed_ips: Vec::new(),
            },
            health: ConnectionHealth::Healthy,
            interface_name: None,
            started_at: None,
        }
    }

    fn connected(name: &str) -> TunnelSnapshot {
        let details = DetailedConnectionInfo {
            interface: format!("utun-{name}"),
            ..Default::default()
        };
        snap(
            name,
            Connection::Connected {
                profile_id: ProfileId::new(name),
                since: SystemTime::now(),
                health: ConnectionHealth::Healthy,
                details: Box::new(details),
            },
        )
    }

    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = Rect::new(0, 0, width, height);
                render(frame, app, area);
            })
            .expect("draw");
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    // ─────────── State 0: no tunnels → ⚠ Real ───────────

    #[test]
    fn empty_registry_renders_disconnected_title_and_real_ip() {
        // 0-tunnel state surfaces the explicit `○ DISCONNECTED` title
        // alongside the Real: IP. The title was removed by the U16
        // header redesign and restored after user feedback — the
        // warning glyph alone wasn't legible enough for the
        // "no VPN at all" state.
        let mut app = App::new_test();
        app.runtime.public_ip = "203.0.113.7".to_string();
        let out = render_to_string(&app, 100, 1);
        assert!(
            out.contains("DISCONNECTED"),
            "expected DISCONNECTED title, got:\n{out}"
        );
        assert!(
            out.contains('\u{25cb}'),
            "expected ○ glyph next to DISCONNECTED, got:\n{out}"
        );
        assert!(out.contains("Real:"), "expected 'Real:' label, got:\n{out}");
        assert!(
            out.contains("203.0.113.7"),
            "expected public IP, got:\n{out}"
        );
        // The ⚠ warning glyph belongs to the no-primary-but-tunnels-up
        // branch; in the genuine 0-tunnel state we use ○ DISCONNECTED.
        assert!(
            !out.contains('\u{26a0}'),
            "0-tunnel branch must not show the ⚠ glyph (that's the no-primary branch's signal):\n{out}"
        );
        // No tunnels strip when count == 0.
        assert!(
            !out.contains("Tunnels:"),
            "no strip expected with 0 tunnels, got:\n{out}"
        );
    }

    #[test]
    fn no_exit_line_renders_title_and_real_ip() {
        // The no-primary-but-tunnels-up branch surfaces a `○ NO EXIT`
        // title that's distinct from both `○ DISCONNECTED` (genuine
        // no-VPN) and the `● CONNECTED (name)` primary line. Vocabulary
        // matches Security Guard's "split-route — no exit" copy.
        use ratatui::style::Modifier;
        let mut app = App::new_test();
        app.runtime.public_ip = "198.51.100.42".to_string();
        let ks = Span::raw(" KS:Off");

        let line = render_no_exit_line(&app, ks);
        let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("NO EXIT"), "expected NO EXIT title:\n{text}");
        assert!(
            text.contains('\u{25cb}'),
            "expected ○ glyph next to NO EXIT (matches DISCONNECTED's glyph for visual consistency):\n{text}"
        );
        assert!(text.contains("Real:"), "expected 'Real:' label:\n{text}");
        assert!(
            text.contains("198.51.100.42"),
            "expected public IP:\n{text}"
        );

        // The NO EXIT title uses WARNING styling, not ERROR — the
        // situation is suboptimal but tunnels ARE up, unlike the
        // genuine no-VPN state.
        let title_span = &line.spans[0];
        assert_eq!(title_span.style.fg, Some(theme::WARNING));
        assert!(title_span.style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn disconnected_and_no_exit_titles_use_different_colors() {
        // Visual distinction: DISCONNECTED (no VPN at all) is ERROR red;
        // NO EXIT (tunnels up, none owning default) is WARNING yellow.
        // Same `○` glyph keeps the family resemblance ("not protected")
        // but the color delta lets users distinguish at a glance.
        let app = App::new_test();
        let ks = Span::raw(" KS:Off");

        let disc = render_disconnected_line(&app, ks.clone());
        let no_exit = render_no_exit_line(&app, ks);

        assert_eq!(disc.spans[0].style.fg, Some(theme::ERROR));
        assert_eq!(no_exit.spans[0].style.fg, Some(theme::WARNING));
    }

    #[test]
    fn empty_registry_does_not_emit_tunnels_label() {
        let app = App::new_test();
        assert_eq!(app.registry.tunnel_count(), 0);
        let out = render_to_string(&app, 80, 1);
        assert!(!out.contains("Tunnels"), "got:\n{out}");
    }

    // ─────────── Strip builders ───────────

    #[test]
    fn strip_full_names_when_budget_is_ample() {
        let snaps = [connected("corp"), connected("lab"), connected("home")];
        let visible: Vec<_> = snaps
            .iter()
            .filter_map(|s| strip_badge(&s.state).map(|(g, c)| (s, g, c)))
            .collect();
        let (width, spans) = build_strip_inner(&visible);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("corp"), "expected full name 'corp': {text}");
        assert!(text.contains("lab"), "expected 'lab': {text}");
        assert!(text.contains("home"), "expected 'home': {text}");
        assert!(width > 0);
    }

    #[test]
    fn narrow_strip_drops_overflow_with_plus_n() {
        let snaps: Vec<TunnelSnapshot> = (0..5).map(|i| connected(&format!("tunnel{i}"))).collect();
        let visible: Vec<_> = snaps
            .iter()
            .filter_map(|s| strip_badge(&s.state).map(|(g, c)| (s, g, c)))
            .collect();
        // Budget tight enough that only ~2 fit.
        let spans = build_narrow_strip(&visible, 10).expect("some fit");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains('+'), "expected overflow marker: {text}");
    }

    #[test]
    fn dotrow_keeps_primary_at_position_zero() {
        // Primary appears first in `visible` because the caller orders it
        // that way; verify the dot-row builder doesn't reorder.
        let snaps = [
            connected("primary"),
            connected("secondary1"),
            connected("secondary2"),
        ];
        let visible: Vec<_> = snaps
            .iter()
            .filter_map(|s| strip_badge(&s.state).map(|(g, c)| (s, g, c)))
            .collect();
        let spans = build_dotrow(&visible, 10).expect("fits");
        // First non-separator span should be the primary's badge char.
        let first_glyph = spans
            .iter()
            .find(|s| !s.content.trim().is_empty())
            .expect("at least one glyph");
        assert_eq!(first_glyph.content.as_ref(), "\u{25cf}"); // ●
    }

    #[test]
    fn append_strip_skips_when_budget_too_small() {
        // Width 5 leaves no room for `│ [●] ` after even a tiny prefix.
        let base = Line::from(vec![Span::raw("XXX")]);
        let snaps = vec![connected("a"), connected("b")];
        let pid = ProfileId::new("a");
        let out = append_tunnels_strip(base.clone(), &snaps, Some(&pid), 5);
        // No new spans appended.
        assert_eq!(
            out.spans.len(),
            base.spans.len(),
            "strip dropped at tiny widths"
        );
    }

    #[test]
    fn append_strip_emits_label_at_wide_widths() {
        let base = Line::from(vec![Span::raw("PRIMARY-LINE")]);
        let snaps = vec![connected("alpha"), connected("bravo")];
        let pid = ProfileId::new("alpha");
        let out = append_tunnels_strip(base, &snaps, Some(&pid), 200);
        let text: String = out.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("Tunnels:"), "expected label, got:\n{text}");
        assert!(text.contains("alpha"), "expected alpha name, got:\n{text}");
        assert!(text.contains("bravo"), "expected bravo name, got:\n{text}");
    }

    #[test]
    fn append_strip_drops_disconnected_entries() {
        let mut disc = connected("ghost");
        disc.state = Connection::Disconnected { last_failure: None };
        let snaps = vec![connected("alpha"), disc];
        let pid = ProfileId::new("alpha");
        let out = append_tunnels_strip(Line::from(vec![Span::raw("X")]), &snaps, Some(&pid), 200);
        let text: String = out.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(text.contains("alpha"), "alpha kept: {text}");
        assert!(!text.contains("ghost"), "ghost dropped: {text}");
    }
}
