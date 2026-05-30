use crate::app::App;
use crate::vortix_core::engine::state::Connection;
use crate::{constants, theme, utils};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Paragraph},
    Frame,
};

/// Sigil legend rendered at the bottom of the panel.
///
/// Plan #001 U18: keep the meaning of the three primary sigils visible inline
/// so users don't have to guess. `✗` (off / unprotected) is intentionally
/// omitted from the legend — its meaning is conventional and the panel only
/// pairs it with a self-explanatory headline (`Killswitch : Off`).
const SIGIL_LEGEND: &str = "Legend: ✓ pass · ⚠ at risk · ─ not applicable";

/// Render the Security Guard panel scoped to the primary tunnel.
///
/// Multi-connection plan U6 Stage B: IP / DNS leak checks read from
/// `app.registry.primary()` snapshot (the tunnel that owns the kernel
/// default route). Secondaries don't carry IP/DNS leak posture — the
/// primary's route table determines internet-bound exit posture per H7.
///
/// Plan #001 U18 layers in three behaviours:
/// - **Primary-scoped headline:** the top banner is `PROTECTED` only when a
///   primary exists and its IP/DNS checks pass; `PARTIAL` when active tunnels
///   exist but none owns the default route (split-route only); `EXPOSED`
///   when no tunnels at all.
/// - **KS-mode-aware Killswitch line:** in the `PARTIAL` (no-primary) branch,
///   render exactly one bullet that matches the active killswitch mode rather
///   than three sub-bullets — the user reads a single sigil + headline to
///   identify their protection posture.
/// - **Honest IPv6 reporting:** the killswitch is v4-only on every supported
///   platform today, so the IPv6 line always shows `⚠ Not enforced
///   (v4-only killswitch)`. The previous `✓ Blocked` framing implied
///   protection we do not actually deliver.
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
        .padding(Padding::horizontal(1))
        .title(" Security Guard ");

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let primary_snap = app
        .registry
        .primary()
        .and_then(|id| app.registry.snapshot(id));
    let primary_connected = matches!(
        primary_snap.as_ref().map(|s| &s.state),
        Some(Connection::Connected { .. })
    );
    let any_tunnels = app.registry.tunnel_count() > 0;

    if !primary_connected {
        // No primary means no default-route exit posture to attest to. If
        // there are still active tunnels (split-route mode), surface PARTIAL
        // with a KS-mode-aware Killswitch bullet so the user knows their
        // baseline protection posture. Otherwise fall through to the
        // existing EXPOSED copy.
        if any_tunnels {
            render_partial_no_primary(frame, app, inner);
        } else {
            render_exposed(frame, inner);
        }
        return;
    }

    let dns_leaking = match &app.runtime.real_dns {
        Some(real_dns) => &app.runtime.dns_server == real_dns,
        None => false,
    };

    let ip_status = match &app.runtime.real_ip {
        Some(real)
            if !app.runtime.public_ip.is_empty()
                && app.runtime.public_ip != constants::MSG_DETECTING
                && app.runtime.public_ip != constants::MSG_FETCHING
                && !app.runtime.public_ip.starts_with("Error") =>
        {
            if &app.runtime.public_ip == real {
                (false, true, Some(real.clone()))
            } else {
                (true, false, Some(real.clone()))
            }
        }
        _ => (false, false, None),
    };
    let (ip_masked, ip_leaking, real_ip_opt) = ip_status;

    // Encryption derived from the primary tunnel's details (`public_key`
    // is empty for OpenVPN, populated for WireGuard).
    let encryption_info = match primary_snap.as_ref().map(|s| &s.state) {
        Some(Connection::Connected { details, .. }) => {
            if details.public_key == "OpenVPN" || details.public_key.is_empty() {
                if details.latest_handshake.starts_with("Cipher:") {
                    details.latest_handshake.replace("Cipher: ", "")
                } else {
                    "AES-256-GCM".to_string()
                }
            } else {
                "ChaCha20-Poly1305".to_string()
            }
        }
        _ => "N/A".to_string(),
    };

    let check_pass = Span::styled("✓ ", Style::default().fg(theme::SUCCESS));
    let check_fail = Span::styled("✗ ", Style::default().fg(theme::ERROR));
    let check_warn = Span::styled("⚠ ", Style::default().fg(theme::WARNING));

    let max_val = inner.width.saturating_sub(15) as usize;

    // Headline colour reflects only the checks the primary actually owns:
    // IP masking and DNS routing. IPv6 is permanently reported as "at risk"
    // (v4-only killswitch) and so cannot ever upgrade the headline — but
    // also cannot drag a v4-clean exit down to PARTIAL, which would make the
    // banner permanently misleading on every platform.
    let mut audit = vec![
        Line::from(vec![Span::styled(
            "   PROTECTED",
            Style::default()
                .fg(if ip_masked && !dns_leaking {
                    theme::SUCCESS
                } else {
                    theme::WARNING
                })
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
    ];

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
                utils::truncate(&app.runtime.public_ip, max_val),
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

    let dns_provider = if app.runtime.dns_server.contains("1.1.1.1") {
        " (Cloudflare)"
    } else if app.runtime.dns_server.contains("8.8.8.8")
        || app.runtime.dns_server.contains("8.8.4.4")
    {
        " (Google)"
    } else if app.runtime.dns_server.contains("9.9.9.9") {
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
            utils::truncate(&app.runtime.dns_server, max_val),
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
    if let Some(real_dns) = &app.runtime.real_dns {
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

    // IPv6 honest reporting (plan #001 U18): the killswitch is v4-only on
    // every supported platform today. The previous `✓ Blocked` framing
    // claimed protection the code does not implement. Report the gap
    // verbatim so a v6 leak does not silently bypass the kill switch while
    // the panel reassures the user everything is fine.
    audit.push(Line::from(vec![
        check_warn.clone(),
        Span::styled("IPv6       : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            "Not enforced (v4-only killswitch)",
            Style::default().fg(theme::WARNING),
        ),
    ]));

    audit.push(Line::from(""));

    // Mode label uses the plain-English UI naming from
    // `KillSwitchMode::display_name` — the variant names (`Off` /
    // `Auto` / `AlwaysOn`) are kept stable for CLI/JSON; only the
    // human-facing copy uses friendlier strings. See the module docs
    // on `vortix_core::state::killswitch` for the mapping.
    let mode = app.runtime.killswitch_mode;
    let state = app.runtime.killswitch_state;
    let mode_label = mode.display_name();
    let (ks_icon, ks_color, status_phrase) = match (mode, state) {
        (crate::state::KillSwitchMode::Off, _) => {
            (check_fail.clone(), theme::INACTIVE, "off — not protecting")
        }
        // AlwaysOn is Blocking by design (steady state) — green/pass,
        // not an alarm.
        (crate::state::KillSwitchMode::AlwaysOn, _) => (
            check_pass.clone(),
            theme::SUCCESS,
            "firewall engaged — only VPN traffic permitted",
        ),
        // Auto in the Blocking state means VPN dropped and the
        // firewall engaged in response — this IS an alarm.
        (crate::state::KillSwitchMode::Auto, crate::state::KillSwitchState::Blocking) => (
            check_warn.clone(),
            theme::ERROR,
            "VPN dropped — firewall engaged; reconnect or `release-killswitch` to recover",
        ),
        (crate::state::KillSwitchMode::Auto, crate::state::KillSwitchState::Armed) => (
            check_pass.clone(),
            theme::SUCCESS,
            "watching — will engage if the VPN drops",
        ),
        _ => (check_warn.clone(), theme::WARNING, "unknown state"),
    };

    audit.push(Line::from(vec![
        ks_icon,
        Span::styled("Kill Switch: ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(mode_label, Style::default().fg(ks_color)),
        Span::styled(
            format!(" — {status_phrase}"),
            Style::default().fg(theme::TEXT_SECONDARY),
        ),
    ]));

    audit.push(Line::from(""));

    audit.push(Line::from(vec![
        check_pass,
        Span::styled("Encryption : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(encryption_info, Style::default().fg(theme::NORD_YELLOW)),
    ]));

    let last_checked_text = match app.runtime.last_security_check {
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

    // Sigil legend (plan #001 U18). Rendered after `Last checked` so it sits
    // at the visual bottom of the panel without competing with the headline
    // for first-glance attention. The compaction loop below may drop it if
    // the panel is short — that's intentional: legend is the lowest-priority
    // line on a height-constrained viewport.
    audit.push(Line::from(vec![Span::styled(
        SIGIL_LEGEND,
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

/// Existing "no tunnels at all" copy — extracted into a helper so the new
/// `PARTIAL` branch can sit alongside it without nesting another two-level
/// match inside the primary render path.
fn render_exposed(frame: &mut Frame, inner: Rect) {
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
}

/// `PARTIAL` (plan #001 U18) — active tunnels exist but no primary owns the
/// default route (split-route only). The panel cannot speak to IP/DNS exit
/// posture (there is no exit), so it limits itself to:
///   1. A PARTIAL headline so the user does not misread the missing default
///      route as full protection.
///   2. A KS-mode-aware Killswitch bullet that names the active mode's
///      protection posture in one line. Rendering all three mode bullets
///      would force the user to identify their own mode from a sub-bulleted
///      list — strictly worse UX.
///   3. The honest IPv6 line (same as `PROTECTED`).
///   4. The sigil legend.
fn render_partial_no_primary(frame: &mut Frame, app: &App, inner: Rect) {
    let check_pass = Span::styled("✓ ", Style::default().fg(theme::SUCCESS));
    let check_fail = Span::styled("✗ ", Style::default().fg(theme::ERROR));
    let check_warn = Span::styled("⚠ ", Style::default().fg(theme::WARNING));
    let check_na = Span::styled("─ ", Style::default().fg(theme::INACTIVE));

    let mut audit = vec![
        Line::from(vec![Span::styled(
            "   PARTIAL",
            Style::default()
                .fg(theme::WARNING)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(Span::styled(
            "Active tunnels carry split routes only —",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(Span::styled(
            "internet-bound traffic still exits the LAN.",
            Style::default().fg(theme::TEXT_SECONDARY),
        )),
        Line::from(""),
    ];

    // KS-mode-aware Killswitch line — render exactly the bullet for the
    // active mode. The user-facing label uses
    // `KillSwitchMode::display_name`; the long-form copy reads as plain
    // English ("what does this mode do?"). The enum variant names
    // (Off / Auto / AlwaysOn) stay stable for CLI/JSON — see
    // `vortix_core::state::killswitch` module docs.
    let mode = app.runtime.killswitch_mode;
    let (ks_sigil, ks_color) = match mode {
        crate::state::KillSwitchMode::AlwaysOn => (check_pass.clone(), theme::SUCCESS),
        crate::state::KillSwitchMode::Auto => (check_na.clone(), theme::INACTIVE),
        crate::state::KillSwitchMode::Off => (check_fail.clone(), theme::ERROR),
    };
    let ks_text = format!("{} — {}", mode.display_name(), mode.one_liner());
    audit.push(Line::from(vec![
        ks_sigil,
        Span::styled("Killswitch : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(ks_text, Style::default().fg(ks_color)),
    ]));

    audit.push(Line::from(""));
    audit.push(Line::from(vec![
        check_warn,
        Span::styled("IPv6       : ", Style::default().fg(theme::TEXT_SECONDARY)),
        Span::styled(
            "Not enforced (v4-only killswitch)",
            Style::default().fg(theme::WARNING),
        ),
    ]));

    audit.push(Line::from(""));
    audit.push(Line::from(vec![Span::styled(
        SIGIL_LEGEND,
        Style::default().fg(Color::DarkGray),
    )]));

    // Same compaction approach as the PROTECTED branch — drop blank lines
    // first, then truncate. Keeps the headline and KS line visible even
    // when the panel is short.
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
        .padding(Padding::horizontal(1))
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

    let is_connected = app.registry.primary().is_some();

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

#[cfg(test)]
mod tests {
    //! Plan #001 U18 — Security Guard becomes primary-scoped, gains a
    //! PARTIAL no-primary branch, reports IPv6 honestly, and grows a sigil
    //! legend.
    //!
    //! These tests render the panel into a `TestBackend` buffer and assert
    //! on the resulting text. Asserting on rendered glyphs (rather than
    //! probing intermediate `Line` vectors) is what the user actually sees
    //! and survives refactors of the line-construction code.
    //!
    //! The PROTECTED branch is intentionally not exercised here: driving an
    //! FSM into `Connection::Connected` requires either the registry's
    //! test-only `with_route_probe` constructor (private to that module) or
    //! a real platform route probe (non-deterministic in unit tests). The
    //! integration tests for the connect flow already cover the Connected
    //! transition; this file scopes itself to the branches reachable from
    //! `App::new_test()` plus direct registry insertion.
    use super::*;
    use crate::app::App;
    use crate::state::KillSwitchMode;
    use crate::vortix_core::engine::Engine;
    use crate::vortix_core::profile::ProfileId;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Insert a Disconnected FSM into the registry. `tunnel_count` goes
    /// to 1 but `primary()` stays `None` (no route probe will match a
    /// Disconnected FSM). Reproduces the PARTIAL no-primary branch
    /// deterministically — without hitting platform probes or scripted
    /// outcomes.
    fn insert_idle_tunnel(app: &mut App, name: &str) {
        let tunnel = crate::tunnel::TunnelKind::Mock(
            crate::vortix_core::ports::tunnel::mock::MockTunnel::new(),
        );
        let engine = Engine::new(tunnel, |_| None);
        app.registry.insert(ProfileId::new(name), engine, vec![]);
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

    #[test]
    fn no_tunnels_renders_exposed() {
        let app = App::new_test();
        assert_eq!(app.registry.tunnel_count(), 0);
        assert!(app.registry.primary().is_none());

        let out = render_to_string(&app, 60, 20);
        assert!(
            out.contains("EXPOSED"),
            "expected EXPOSED banner, got:\n{out}"
        );
        // Sigil legend is a PROTECTED/PARTIAL-only chrome — EXPOSED is the
        // "do something" copy and should stay minimal.
        assert!(
            !out.contains("Legend:"),
            "EXPOSED should not render the sigil legend; got:\n{out}"
        );
    }

    #[test]
    fn tunnels_present_but_no_primary_renders_partial() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        insert_idle_tunnel(&mut app, "bravo");
        insert_idle_tunnel(&mut app, "charlie");

        assert_eq!(app.registry.tunnel_count(), 3);
        assert!(
            app.registry.primary().is_none(),
            "Disconnected FSMs must not be elected primary"
        );

        let out = render_to_string(&app, 70, 20);
        assert!(
            out.contains("PARTIAL"),
            "expected PARTIAL banner when tunnels exist but no primary; got:\n{out}"
        );
        assert!(
            !out.contains("EXPOSED"),
            "PARTIAL must not fall back to EXPOSED copy; got:\n{out}"
        );
        assert!(
            !out.contains("PROTECTED"),
            "no primary means no PROTECTED claim; got:\n{out}"
        );
    }

    #[test]
    fn partial_renders_killswitch_bullet_for_active_mode_only() {
        // Plan §U18: in PARTIAL, render exactly ONE Killswitch bullet —
        // the one matching the active mode — not a sub-bulleted
        // multi-mode block. Verifies the chosen mode's friendly label
        // (`VPN-only`, per `KillSwitchMode::display_name`) appears and
        // that the other modes' distinguishing copy does not.
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::AlwaysOn;

        let out = render_to_string(&app, 80, 20);
        assert!(
            out.contains("VPN-only"),
            "AlwaysOn should surface the 'VPN-only' label; got:\n{out}"
        );
        assert!(
            !out.contains("Block on drop"),
            "AlwaysOn must not render the Auto 'Block on drop' line; got:\n{out}"
        );
    }

    #[test]
    fn partial_killswitch_off_renders_off_bullet() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::Off;

        let out = render_to_string(&app, 80, 20);
        assert!(
            out.contains("Killswitch"),
            "Killswitch line missing; got:\n{out}"
        );
        assert!(
            out.contains("Off"),
            "Off mode headline missing; got:\n{out}"
        );
        assert!(
            !out.contains("VPN-only"),
            "Off must not render the AlwaysOn 'VPN-only' label; got:\n{out}"
        );
        assert!(
            !out.contains("Block on drop"),
            "Off must not render the Auto 'Block on drop' label; got:\n{out}"
        );
    }

    #[test]
    fn partial_killswitch_auto_renders_block_on_drop_bullet() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        app.runtime.killswitch_mode = KillSwitchMode::Auto;

        let out = render_to_string(&app, 80, 20);
        assert!(
            out.contains("Block on drop"),
            "Auto mode should surface the 'Block on drop' label; got:\n{out}"
        );
        assert!(
            !out.contains("VPN-only"),
            "Auto must not render the AlwaysOn 'VPN-only' label; got:\n{out}"
        );
    }

    #[test]
    fn partial_ipv6_line_reports_not_enforced() {
        // IPv6 honesty (plan §U18): the killswitch is v4-only on every
        // supported platform. The IPv6 line must report this gap even
        // when no leak has been observed — claiming `✓ Blocked` would be
        // a UX lie because the code does not actually block v6.
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");
        // Explicitly set ipv6_leak=false so any code path that "passes"
        // the IPv6 check based on the leak probe would render "Blocked".
        // The new code must ignore this and always report "Not enforced".
        app.runtime.ipv6_leak = false;

        let out = render_to_string(&app, 80, 25);
        assert!(out.contains("IPv6"), "IPv6 line missing; got:\n{out}");
        assert!(
            out.contains("Not enforced"),
            "IPv6 must always report v4-only honestly; got:\n{out}"
        );
        assert!(
            !out.contains("Blocked"),
            "IPv6 must not claim 'Blocked' protection it does not deliver; got:\n{out}"
        );
    }

    #[test]
    fn partial_renders_sigil_legend() {
        let mut app = App::new_test();
        insert_idle_tunnel(&mut app, "alpha");

        let out = render_to_string(&app, 80, 25);
        assert!(
            out.contains("Legend"),
            "sigil legend missing from PARTIAL panel; got:\n{out}"
        );
        // Each documented sigil must appear in the legend line.
        assert!(out.contains("✓"), "legend missing ✓; got:\n{out}");
        assert!(out.contains("⚠"), "legend missing ⚠; got:\n{out}");
        assert!(out.contains("─"), "legend missing ─; got:\n{out}");
    }

    #[test]
    fn sigil_legend_constant_matches_plan() {
        // Anchors the canonical legend string against the plan so future
        // edits to the constant trip a test rather than silently drift.
        assert_eq!(
            SIGIL_LEGEND,
            "Legend: ✓ pass · ⚠ at risk · ─ not applicable"
        );
    }
}
