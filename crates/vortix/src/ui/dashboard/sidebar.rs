//! Sidebar: profile catalog with multi-tunnel status badges.
//!
//! ## Badge taxonomy
//!
//! The sidebar status char migrated from the legacy
//! `✓ / … / ⏻` vocabulary to a richer set that distinguishes connect-attempt
//! states, awaits user input, and surfaces failures:
//!
//! ```text
//!   '●'  Connected               → theme::current().success (bold if primary)
//!   '◐'  Connecting              → theme::current().warning
//!   '↻'  Reconnecting            → theme::current().warning + Modifier::DIM
//!   '◑'  Disconnecting           → theme::current().warning
//!   '?'  AwaitingCredentials     → theme::current().warning
//!   '✗'  Disconnected w/ failure → theme::current().error
//!   ' '  Disconnected, no fail   → Color::Reset
//! ```
//!
//! The primary tunnel (kernel-truth holder of the default route, per
//! `App::primary_id`) is suffixed with ` *` after the profile name to
//! cross-correlate with the header's primary marker.
//!
//! ## Risk annotations
//!
//! A `!` annotation may follow the status char (`●!`) to surface per-tunnel
//! risk states that the user should drill into Connection Details to resolve.
//! Today the taxonomy surfaces **mode-mismatch risk**: a tunnel whose declared `AllowedIPs`
//! claim `0/0` but which did not win the kernel default route — represented in
//! the engine as `Role::AddressableSuppressed`. The fwmark-hijack risk
//! annotation (also `!`, ) lands when a follow-up wires
//! the WG-config-aware predicate; the rendering pipeline here already reserves
//! the column so a follow-up only has to extend the predicate, not the layout.
//!
//! ## Width discipline
//!
//! `fixed_cols = 2 + 4 + 7 + 3 = 16` (status, proto, time, inter-column
//! gaps). The primary `*` suffix consumes 2 chars; at a 21-char inner width
//! `name_budget = 21 - 16 - 2 = 3`. Narrower, the `*` marker is hidden and
//! the name collapses to a stub — the header retains the primary signal.
//!
//! ## Accessibility note
//!
//! `↻` (U+21BB) and `◐` both render in `theme::current().warning`; the `↻` glyph carries
//! `Modifier::DIM` to keep monochrome / color-blind users discriminating by
//! shape alone. Both glyphs are visually distinct shapes; no monochrome-mode
//! regression. `unicode-width` reports `↻` as width=1 — verified by unit test
//! `unicode_width_of_reconnecting_glyph_is_one` — which is load-bearing for
//! the `fixed_cols` arithmetic above.

use crate::app::App;
use crate::app::Role;
use crate::control::{Phase, TunnelView};
use crate::profile::ProfileId;
use crate::ui::theme;
use ratatui::{
    layout::{Alignment, Constraint, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table,
    },
    Frame,
};

/// Per-row status badge derived from the tunnel's phase.
///
/// Returns the (glyph, style) pair for the status cell. `None` means the row
/// is fully disconnected with no failure — caller renders a blank cell.
///
/// All visual specs (glyph + color + modifiers) come from
/// [`crate::ui::sigils::CATALOG`] — the single source of truth shared
/// between this renderer and the `?` help overlay's Sigils tab.
fn status_badge_for(
    tunnel: &TunnelView,
    protocol: Option<crate::profile::ProtocolKind>,
) -> (&'static str, Style) {
    let s = crate::ui::sigils::sigil(status_sigil_id(tunnel, protocol));
    (s.glyph, s.style())
}

fn status_sigil_id(
    tunnel: &TunnelView,
    protocol: Option<crate::profile::ProtocolKind>,
) -> crate::ui::sigils::SigilId {
    use crate::ui::sigils::SigilId;
    match tunnel.phase {
        Phase::Up => {
            // the state-authority contract: Connected entries whose
            // interface name vortix couldn't reliably attribute to a PID
            // (current case: externally-started OpenVPN on macOS where
            // the scanner's ifconfig-scan fallback collides across
            // PIDs) render with a muted/dim treatment. They ARE up;
            // vortix just can't verify their routing posture.
            if tunnel.details.interface_authoritative {
                SigilId::Connected
            } else {
                SigilId::ConnectedUnauthoritative
            }
        }
        Phase::Starting => {
            if matches!(protocol, Some(crate::profile::ProtocolKind::WireGuard)) {
                SigilId::Handshaking
            } else {
                SigilId::Connecting
            }
        }
        Phase::Waiting { .. } => SigilId::Reconnecting,
        Phase::Stopping => SigilId::Disconnecting,
        Phase::AwaitingCredentials => SigilId::AwaitingInput,
    }
}

/// Does this snapshot warrant a `!` risk annotation in the sidebar?
///
/// Today: `Role::AddressableSuppressed` — declared 0/0 `AllowedIPs` but did not
/// win the kernel default route (mode-mismatch). A follow-up will extend this to
/// also include WG-secondary-missing-FwMark while primary holds 0/0; the
/// signature returns a `bool` so the predicate can grow without churning the
/// render path.
fn has_risk_annotation(role: &Role, health: &crate::tunnel::ConnectionHealth) -> bool {
    matches!(role, Role::AddressableSuppressed { .. })
        || matches!(health, crate::tunnel::ConnectionHealth::Degraded { .. })
}

/// Should the primary `*` suffix render given the available name-cell width?
///
/// At `inner.width == 21` → `name_cell_width = 5`,
/// `name_budget = 3` after the 2-char ` *` reserve, which is the minimum
/// usable name stub. Below that the `*` hides; the header retains the
/// cross-surface primary signal so no information is lost.
fn should_show_primary_marker(is_primary: bool, name_cell_width: usize) -> bool {
    const PRIMARY_RESERVE: usize = 2;
    const MIN_NAME_BUDGET_FOR_PRIMARY: usize = 3;
    is_primary && name_cell_width.saturating_sub(PRIMARY_RESERVE) >= MIN_NAME_BUDGET_FOR_PRIMARY
}

/// Per-row presentation derived from the engine snapshot, decoupled from layout.
struct RowSignal {
    /// Status glyph + style; `None` → blank status cell.
    badge: Option<(&'static str, Style)>,
    /// Color used for the active-state name accent. `Color::Reset` when no
    /// active marker is present.
    accent: Color,
    /// True if this row is the kernel-truth primary tunnel.
    is_primary: bool,
    /// True if a `!` risk annotation should follow the status char.
    risk: bool,
    /// True if the engine has a tunnel for this profile at all.
    is_active: bool,
}

impl RowSignal {
    fn empty() -> Self {
        Self {
            badge: None,
            accent: Color::Reset,
            is_primary: false,
            risk: false,
            is_active: false,
        }
    }
}

fn signal_for(
    app: &App,
    profile_id: &ProfileId,
    protocol: crate::profile::ProtocolKind,
) -> RowSignal {
    let Some(tunnel) = app.tunnel(profile_id) else {
        return RowSignal::empty();
    };
    let badge = Some(status_badge_for(tunnel, Some(protocol)));
    let accent = badge.map_or(Color::Reset, |(_, style)| style.fg.unwrap_or(Color::Reset));
    RowSignal {
        badge,
        accent,
        is_primary: app.primary_id() == Some(profile_id),
        risk: has_risk_annotation(&app.role(tunnel), &tunnel.health),
        is_active: true,
    }
}

/// One profile row: status badge, name (with the primary `*`), protocol
/// tag and last-used time. Selection owns the foreground of every cell.
fn profile_row(
    profile: &crate::config::profiles::VpnProfile,
    idx: usize,
    is_selected: bool,
    signal: &RowSignal,
    name_cell_width: usize,
) -> Row<'static> {
    // Status cell: badge taxonomy + optional `!` risk annotation.
    // Numeric prefix (1..=9) remains the affordance for keyboard
    // quick-select; once a row is active the badge replaces the number
    // so the user sees state, not muscle-memory.
    let status_cell = if let Some((glyph, style)) = signal.badge {
        let badge_style = if is_selected {
            style.fg(theme::current().row_selected_fg)
        } else {
            style
        };
        let mut spans = vec![Span::styled(glyph, badge_style)];
        if signal.risk {
            spans.push(Span::styled(
                "!",
                Style::default().fg(row_fg(is_selected, theme::current().warning)),
            ));
        }
        Cell::from(Line::from(spans))
    } else if idx < 9 {
        Cell::from(Span::styled(
            format!("{}", idx + 1),
            Style::default().fg(row_fg(is_selected, theme::current().text_secondary)),
        ))
    } else {
        Cell::from(Span::styled(" ", Style::default()))
    };

    // Primary marker: shown only when there's enough room for both a
    // 2-char ` *` suffix AND a 3-char minimum name stub. Below that we
    // suppress the marker (header still carries it cross-surface).
    let show_primary_marker = should_show_primary_marker(signal.is_primary, name_cell_width);
    let primary_reserve = if show_primary_marker { 2 } else { 0 };
    let name_budget = name_cell_width.saturating_sub(primary_reserve).max(1);

    let name_style = if is_selected {
        Style::default()
            .fg(theme::current().row_selected_fg)
            .add_modifier(Modifier::BOLD)
    } else if signal.is_primary {
        Style::default()
            .fg(signal.accent)
            .add_modifier(Modifier::BOLD)
    } else if signal.is_active {
        Style::default().fg(signal.accent)
    } else {
        Style::default().fg(theme::current().inactive)
    };

    let display_name = crate::ui::helpers::truncate_to_width(&profile.name, name_budget);
    let mut name_spans = vec![Span::styled(display_name, name_style)];
    if show_primary_marker {
        name_spans.push(Span::styled(
            " *",
            Style::default()
                .fg(row_fg(is_selected, signal.accent))
                .add_modifier(Modifier::BOLD),
        ));
    }
    let name_cell = Cell::from(Line::from(name_spans));

    let proto_icon = match profile.protocol {
        crate::profile::ProtocolKind::WireGuard => "WG",
        crate::profile::ProtocolKind::OpenVpn => "OV",
    };
    let proto_color = if is_selected {
        theme::current().row_selected_fg
    } else if signal.is_active {
        signal.accent
    } else {
        theme::current().text_secondary
    };

    let time_str = if let Some(last_used) = profile.last_used {
        let relative = crate::ui::helpers::format_relative_time(last_used);
        if !relative.ends_with("ago") && !relative.is_empty() {
            format!("{relative} ago")
        } else {
            relative
        }
    } else {
        "never".to_string()
    };

    let row_style = if is_selected {
        Style::default().bg(theme::current().row_selected_bg)
    } else {
        Style::default()
    };

    let proto_cell = Cell::from(Span::styled(proto_icon, Style::default().fg(proto_color)));
    let time_cell = Cell::from(Span::styled(
        time_str,
        Style::default().fg(row_fg(is_selected, theme::current().text_secondary)),
    ));

    Row::new(vec![status_cell, name_cell, proto_cell, time_cell]).style(row_style)
}

/// `fallback`, unless the row is selected — selection owns the foreground.
fn row_fg(is_selected: bool, fallback: Color) -> Color {
    if is_selected {
        theme::current().row_selected_fg
    } else {
        fallback
    }
}

/// The sidebar with no profiles at all: what's missing, and the key to fix it.
fn render_empty_state(frame: &mut Frame, inner: Rect) {
    let empty_msg = vec![
        Line::from(""),
        Line::from(Span::styled(
            "No profiles yet",
            Style::default().fg(theme::current().text_secondary),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "Press ",
                Style::default().fg(theme::current().key_hint_desc),
            ),
            Span::styled(
                "[i]",
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                " to import",
                Style::default().fg(theme::current().key_hint_desc),
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(empty_msg).alignment(Alignment::Center),
        inner,
    );
}

pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };

    let sort_label = app.runtime.sort_order.label();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1))
        .title(format!(" Profiles [{sort_label}] "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if app.runtime.profiles.is_empty() && app.tunnel_count() == 0 {
        render_empty_state(frame, inner);
        return;
    }

    // Column arithmetic: status(2) + proto(4) + time(7) + 3 inter-column gaps.
    let fixed_cols: u16 = 2 + 4 + 7 + 3;
    // Width budget available to the name cell before primary `*` reserve.
    let name_cell_width = inner.width.saturating_sub(fixed_cols) as usize;
    let items: Vec<Row> = app
        .runtime
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let signal = signal_for(app, &p.id, p.protocol);
            profile_row(
                p,
                idx,
                app.profile_list_state.selected() == Some(idx),
                &signal,
                name_cell_width,
            )
        })
        .collect();

    let table = Table::new(
        items,
        [
            Constraint::Length(2), // Status: badge glyph (+ optional `!`)
            Constraint::Min(3),    // Profile name (flex, with optional ` *`)
            Constraint::Length(4), // Protocol (WG/OV)
            Constraint::Length(7), // Last used time: "59m ago", "never"
        ],
    );
    frame.render_stateful_widget(table, inner, &mut app.profile_list_state);

    // Scrollbar Logic
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::current().nord_polar_night_4))
        .thumb_style(Style::default().fg(theme::current().accent_primary));

    let mut scrollbar_state = ScrollbarState::new(
        app.runtime
            .profiles
            .len()
            .saturating_sub(inner.height as usize),
    )
    .position(app.profile_list_state.selected().unwrap_or(0));

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

#[cfg(test)]
mod tests {
    //! Sidebar badge tests. Cover the badge taxonomy migration, primary `*`
    //! marker, `!` risk annotation for mode-mismatch (`AddressableSuppressed`),
    //! and the narrow-width fallback at the 21-char inner-width boundary.
    //! Earlier smoke tests (empty-state, row rendering) remain.
    use super::*;
    use crate::app::App;
    use crate::app::Role;
    use crate::cidr::Cidr;
    use crate::config::profiles::VpnProfile;
    use crate::profile::ProfileId;
    use crate::profile::ProtocolKind;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;
    use unicode_width::UnicodeWidthStr;

    fn make_profile(name: &str) -> VpnProfile {
        VpnProfile {
            id: crate::profile::ProfileId::new(name),
            name: name.to_string(),
            protocol: ProtocolKind::WireGuard,
            location: String::new(),
            config_path: PathBuf::from(format!("/tmp/{name}.conf")),
            last_used: None,
            group: None,
        }
    }

    fn snap_connected(name: &str) -> TunnelView {
        crate::app::connection::test_view(name, Phase::Up)
    }

    fn snap_connecting(name: &str) -> TunnelView {
        crate::app::connection::test_view(name, Phase::Starting)
    }

    fn snap_reconnecting(name: &str) -> TunnelView {
        crate::app::connection::test_view(name, Phase::Waiting { retry_at: None })
    }

    fn render_to_string(app: &mut App, width: u16, height: u16) -> String {
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
    fn no_tunnels_and_empty_profiles_renders_no_profiles_empty_state() {
        let mut app = App::new_test();
        assert_eq!(app.tunnel_count(), 0);
        assert!(app.runtime.profiles.is_empty());

        let out = render_to_string(&mut app, 40, 10);
        assert!(
            out.contains("No profiles yet"),
            "expected empty-state copy, got:\n{out}"
        );
    }

    /// The sidebar is 26 columns wide in an 80-column terminal.
    #[test]
    fn a_short_name_is_readable_at_80_columns() {
        let mut app = App::new_test();
        app.runtime.profiles = vec![make_profile("wg08")];
        let out = render_to_string(&mut app, 26, 6);
        assert!(out.contains("wg08"), "got:\n{out}");
    }

    #[test]
    fn n_profiles_render_n_rows() {
        let mut app = App::new_test();
        app.runtime.profiles = vec![
            make_profile("alpha"),
            make_profile("bravo"),
            make_profile("charlie"),
        ];

        let out = render_to_string(&mut app, 60, 10);
        assert!(!out.contains("No profiles yet"), "got:\n{out}");
        assert!(out.contains("alpha"), "alpha row missing:\n{out}");
        assert!(out.contains("bravo"), "bravo row missing:\n{out}");
        assert!(out.contains("charlie"), "charlie row missing:\n{out}");
    }

    #[test]
    fn selected_row_uses_one_contrasting_foreground_in_every_fixed_theme() {
        for choice in [
            crate::ui::theme::ThemeChoice::Synthwave,
            crate::ui::theme::ThemeChoice::CatppuccinMocha,
            crate::ui::theme::ThemeChoice::Dracula,
            crate::ui::theme::ThemeChoice::Nord,
            crate::ui::theme::ThemeChoice::GruvboxDark,
            crate::ui::theme::ThemeChoice::TokyoNight,
        ] {
            let mut app = App::new_test();
            app.runtime.profiles = vec![make_profile("selected")];
            app.profile_list_state.select(Some(0));
            let mut terminal = Terminal::new(TestBackend::new(60, 6)).expect("terminal");
            crate::ui::theme::with_choice(choice, || {
                terminal
                    .draw(|frame| render(frame, &mut app, Rect::new(0, 0, 60, 6)))
                    .expect("draw");
            });

            let palette = choice.palette();
            let selected_cells: Vec<_> = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .filter(|cell| {
                    cell.bg == palette.row_selected_bg && !cell.symbol().trim().is_empty()
                })
                .collect();
            assert!(!selected_cells.is_empty(), "{choice:?}");
            assert!(
                selected_cells
                    .iter()
                    .all(|cell| cell.fg == palette.row_selected_fg),
                "{choice:?} selected row used mixed foregrounds: {selected_cells:?}"
            );
        }
    }

    #[test]
    fn no_tunnels_yields_no_active_marker_for_any_profile() {
        let app = App::new_test();
        let sig = signal_for(&app, &ProfileId::new("anything"), ProtocolKind::WireGuard);
        assert!(!sig.is_active);
        assert!(sig.badge.is_none());
        assert!(!sig.is_primary);
        assert!(!sig.risk);
    }

    // ── badge taxonomy ────────────────────────────────────────────────

    #[test]
    fn connected_snapshot_renders_filled_circle_glyph() {
        let snap = snap_connected("vpn1");
        let (glyph, _) = status_badge_for(&snap, Some(ProtocolKind::WireGuard));
        assert_eq!(glyph, "●");
    }

    #[test]
    fn connecting_snapshot_renders_half_circle_glyph() {
        let snap = snap_connecting("vpn1");
        let (glyph, _) = status_badge_for(&snap, Some(ProtocolKind::WireGuard));
        assert_eq!(glyph, "◐");
    }

    #[test]
    fn connecting_sigil_identity_is_protocol_specific() {
        let snap = snap_connecting("vpn1");
        assert_eq!(
            status_sigil_id(&snap, Some(ProtocolKind::WireGuard)),
            crate::ui::sigils::SigilId::Handshaking
        );
        assert_eq!(
            status_sigil_id(&snap, Some(ProtocolKind::OpenVpn)),
            crate::ui::sigils::SigilId::Connecting
        );
    }

    #[test]
    fn unauthoritative_connected_badge_renders_dim_grey() {
        // the state-authority contract: when a Connected tunnel's
        // iface can't be reliably attributed to its PID (current case:
        // externally-started OpenVPN on macOS where the scanner's
        // ifconfig-scan fallback collides across PIDs), the row's
        // status badge must visually distinguish from a fully-tracked
        // Connected tunnel.
        let mut snap = snap_connected("vpn1");
        snap.details.interface_authoritative = false;
        let (glyph, style) = status_badge_for(&snap, Some(ProtocolKind::WireGuard));
        assert_eq!(glyph, "●", "still Connected — glyph stays a filled dot");
        assert!(
            style.add_modifier.contains(Modifier::DIM),
            "unauthoritative Connected must dim to distinguish from fully-tracked Connected — got {style:?}"
        );
        // And the foreground color is INACTIVE rather than SUCCESS so
        // monochrome / colorblind users still see the difference via
        // value/lightness.
        assert_eq!(
            style.fg,
            Some(theme::current().inactive),
            "unauthoritative Connected must use the inactive color"
        );
    }

    #[test]
    fn authoritative_connected_badge_renders_bright_green_no_dim() {
        // Inverse check: a normal Connected tunnel (interface_authoritative
        // defaults to true) keeps the bright SUCCESS color and no DIM
        // modifier.
        let snap = snap_connected("vpn1");
        let (glyph, style) = status_badge_for(&snap, Some(ProtocolKind::WireGuard));
        assert_eq!(glyph, "●");
        assert!(!style.add_modifier.contains(Modifier::DIM));
        assert_eq!(style.fg, Some(theme::current().success));
    }

    #[test]
    fn reconnecting_snapshot_renders_reload_glyph_dim() {
        let snap = snap_reconnecting("vpn1");
        let (glyph, style) = status_badge_for(&snap, Some(ProtocolKind::WireGuard));
        assert_eq!(glyph, "↻");
        assert!(
            style.add_modifier.contains(Modifier::DIM),
            "reconnecting must dim to distinguish from connecting under monochrome — got {style:?}"
        );
    }

    // ── width discipline ──────────────────────────────────────────────

    #[test]
    fn unicode_width_of_reconnecting_glyph_is_one() {
        // Load-bearing for fixed_cols arithmetic: if `↻` were width=2 the
        // status column (Length(2)) would overflow into the name cell.
        assert_eq!(
            UnicodeWidthStr::width("↻"),
            1,
            "↻ (U+21BB) must report width=1; rendering arithmetic depends on it"
        );
    }

    #[test]
    fn unicode_width_of_badge_glyphs_all_one() {
        for g in ["●", "◐", "↻", "◑", "?", "✗", "!", "*"] {
            assert_eq!(
                UnicodeWidthStr::width(g),
                1,
                "badge glyph `{g}` must be width=1"
            );
        }
    }

    // ── primary `*` marker ────────────────────────────────────────────

    #[test]
    fn primary_marker_shown_when_name_cell_width_is_five() {
        // inner.width=21, fixed_cols=16 → name_cell_width=5 → name_budget=3.
        assert!(should_show_primary_marker(true, 5));
    }

    #[test]
    fn primary_marker_hidden_when_name_cell_width_is_four() {
        // inner.width=20, fixed_cols=16 → name_cell_width=4 → name_budget=2.
        assert!(!should_show_primary_marker(true, 4));
    }

    #[test]
    fn primary_marker_hidden_when_not_primary() {
        // Even at generous widths, non-primary rows never carry the marker.
        assert!(!should_show_primary_marker(false, 80));
    }

    #[test]
    fn signal_for_marks_primary_when_id_matches() {
        let snap = snap_connected("corp");
        let mut app = App::new_test();
        app.set_tunnels_for_test(vec![snap], Some(ProfileId::new("corp")));
        let sig = signal_for(&app, &ProfileId::new("corp"), ProtocolKind::WireGuard);
        assert!(sig.is_primary);
        assert!(sig.is_active);
        assert_eq!(sig.badge.map(|(g, _)| g), Some("●"));
    }

    #[test]
    fn signal_for_does_not_mark_primary_for_other_rows() {
        let snap = snap_connected("corp");
        let mut app = App::new_test();
        app.set_tunnels_for_test(vec![snap], Some(ProfileId::new("corp")));
        let sig = signal_for(&app, &ProfileId::new("other"), ProtocolKind::WireGuard);
        assert!(!sig.is_primary);
        assert!(!sig.is_active);
    }

    // ── risk annotation ───────────────────────────────────────────────

    #[test]
    fn addressable_suppressed_role_triggers_risk_annotation() {
        let snap = snap_connected("vpn1");
        let role = Role::AddressableSuppressed {
            allowed_ips: vec![Cidr {
                addr: "0.0.0.0".parse().unwrap(),
                prefix_len: 0,
            }],
        };
        assert!(
            has_risk_annotation(&role, &snap.health),
            "AddressableSuppressed role surfaces mode-mismatch `!` annotation"
        );
    }

    #[test]
    fn addressable_role_no_risk_annotation() {
        let snap = snap_connected("vpn1");
        let role = Role::Addressable {
            allowed_ips: vec![],
        };
        assert!(!has_risk_annotation(&role, &snap.health));
    }

    #[test]
    fn primary_role_no_risk_annotation() {
        let snap = snap_connected("vpn1");
        let role = Role::Primary {
            allowed_ips: vec![],
        };
        assert!(!has_risk_annotation(&role, &snap.health));
    }
}
