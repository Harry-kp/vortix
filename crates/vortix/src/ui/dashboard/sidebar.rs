//! Sidebar: profile catalog with multi-tunnel status badges (plan #001 U15).
//!
//! ## Badge taxonomy (U15)
//!
//! Per plan section U15, the sidebar status char migrates from the legacy
//! `✓ / … / ⏻` vocabulary to a richer set that distinguishes connect-attempt
//! states, awaits user input, and surfaces failures:
//!
//! ```text
//!   '●'  Connected               → theme::SUCCESS (bold if primary)
//!   '◐'  Connecting              → theme::WARNING
//!   '↻'  Reconnecting            → theme::WARNING + Modifier::DIM
//!   '◑'  Disconnecting           → theme::WARNING
//!   '?'  AwaitingUserInput       → theme::WARNING
//!   '✗'  Disconnected w/ failure → theme::ERROR
//!   ' '  Disconnected, no fail   → Color::Reset
//! ```
//!
//! The primary tunnel (kernel-truth holder of the default route, per
//! `TunnelRegistry::primary`) is suffixed with ` *` after the profile name to
//! cross-correlate with the header's primary marker.
//!
//! ## Risk annotations
//!
//! A `!` annotation may follow the status char (`●!`) to surface per-tunnel
//! risk states that the user should drill into Connection Details to resolve.
//! Today U15 surfaces **mode-mismatch risk**: a tunnel whose declared `AllowedIPs`
//! claim `0/0` but which did not win the kernel default route — represented in
//! the registry as `Role::AddressableSuppressed`. The fwmark-hijack risk
//! annotation (also `!`, per plan §U17, lines 1044-1045) lands when U17 wires
//! the WG-config-aware predicate; the rendering pipeline here already reserves
//! the column so U17 only has to extend the predicate, not the layout.
//!
//! ## Width discipline
//!
//! Per plan U15 (line 960), `fixed_cols = 2 + 4 + 10 + 3 = 19` (status, proto,
//! time, inter-column gaps). The primary `*` suffix consumes 2 chars; at the
//! 24-char inner-width boundary `name_budget = 24 - 19 - 2 = 3`, which is the
//! minimum that still renders the status glyph plus a 3-char name stub. Below
//! 24 chars of inner width, the `*` marker is hidden and the name collapses
//! to a stub — the header retains the cross-surface primary signal.
//!
//! ## Accessibility note (plan U15 line 975)
//!
//! `↻` (U+21BB) and `◐` both render in `theme::WARNING`; the `↻` glyph carries
//! `Modifier::DIM` to keep monochrome / color-blind users discriminating by
//! shape alone. Both glyphs are visually distinct shapes; no monochrome-mode
//! regression. `unicode-width` reports `↻` as width=1 — verified by unit test
//! `unicode_width_of_reconnecting_glyph_is_one` — which is load-bearing for
//! the `fixed_cols` arithmetic above.

use crate::app::App;
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::engine::{Role, TunnelSnapshot};
use crate::vortix_core::profile::ProfileId;
use crate::{theme, utils};
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

/// Per-row status badge derived from a registry snapshot.
///
/// Returns the (glyph, style) pair for the status cell. `None` means the row
/// is fully disconnected with no failure — caller renders a blank cell.
///
/// All visual specs (glyph + color + modifiers) come from
/// [`crate::ui::sigils::CATALOG`] — the single source of truth shared
/// between this renderer and the `?` help overlay's Sigils tab.
fn status_badge_for(snapshot: &TunnelSnapshot) -> Option<(&'static str, Style)> {
    use crate::ui::sigils::{sigil, SigilId};
    let id = match &snapshot.state {
        Connection::Connected { details, .. } => {
            // R4 of the state-authority contract: Connected entries whose
            // interface name vortix couldn't reliably attribute to a PID
            // (current case: externally-started OpenVPN on macOS where
            // the scanner's ifconfig-scan fallback collides across
            // PIDs) render with a muted/dim treatment. They ARE up;
            // vortix just can't verify their routing posture.
            if details.interface_authoritative {
                SigilId::Connected
            } else {
                SigilId::ConnectedUnauthoritative
            }
        }
        Connection::Connecting { .. } => SigilId::Connecting,
        Connection::Reconnecting { .. } => SigilId::Reconnecting,
        Connection::Disconnecting { .. } => SigilId::Disconnecting,
        Connection::AwaitingUserInput { .. } => SigilId::AwaitingInput,
        Connection::Disconnected {
            last_failure: Some(_),
        } => SigilId::Failed,
        Connection::Disconnected { last_failure: None } => return None,
    };
    let s = sigil(id);
    Some((s.glyph, s.style()))
}

/// Does this snapshot warrant a `!` risk annotation in the sidebar?
///
/// Today: `Role::AddressableSuppressed` — declared 0/0 `AllowedIPs` but did not
/// win the kernel default route (mode-mismatch). Plan U17 will extend this to
/// also include WG-secondary-missing-FwMark while primary holds 0/0; the
/// signature returns a `bool` so the predicate can grow without churning the
/// render path.
fn has_risk_annotation(snapshot: &TunnelSnapshot) -> bool {
    matches!(snapshot.role, Role::AddressableSuppressed { .. })
}

/// Should the primary `*` suffix render given the available name-cell width?
///
/// Plan U15 line 960: at `inner.width == 24` → `name_cell_width = 5`,
/// `name_budget = 3` after the 2-char ` *` reserve, which is the minimum
/// usable name stub. Below that the `*` hides; the header retains the
/// cross-surface primary signal so no information is lost.
fn should_show_primary_marker(is_primary: bool, name_cell_width: usize) -> bool {
    const PRIMARY_RESERVE: usize = 2;
    const MIN_NAME_BUDGET_FOR_PRIMARY: usize = 3;
    is_primary && name_cell_width.saturating_sub(PRIMARY_RESERVE) >= MIN_NAME_BUDGET_FOR_PRIMARY
}

/// Per-row presentation derived from registry data, decoupled from layout.
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
    /// True if the registry holds a snapshot for this profile at all.
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
    snapshots: &[TunnelSnapshot],
    primary: Option<&ProfileId>,
    profile_name: &str,
) -> RowSignal {
    let Some(snap) = snapshots
        .iter()
        .find(|s| s.profile_id.as_str() == profile_name)
    else {
        return RowSignal::empty();
    };
    let badge = status_badge_for(snap);
    let accent = badge.map_or(Color::Reset, |(_, style)| style.fg.unwrap_or(Color::Reset));
    let is_primary = primary.is_some_and(|p| p.as_str() == profile_name);
    RowSignal {
        badge,
        accent,
        is_primary,
        risk: has_risk_annotation(snap),
        is_active: true,
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Sidebar);
    let border_style = if is_focused {
        Style::default().fg(theme::BORDER_FOCUSED)
    } else {
        Style::default().fg(theme::BORDER_DEFAULT)
    };

    let sort_label = app.runtime.sort_order.label();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .padding(Padding::horizontal(1))
        .title(format!(" Profiles [{sort_label}] "));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // U6 Stage A: snapshots come from the registry; profile catalog still on engine.
    let snapshots = app.registry.snapshot_all();
    let primary = app.registry.primary().cloned();

    if app.runtime.profiles.is_empty() && snapshots.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "No profiles yet",
                Style::default().fg(theme::TEXT_SECONDARY),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "[i]",
                    Style::default()
                        .fg(theme::ACCENT_PRIMARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" to import", Style::default().fg(Color::DarkGray)),
            ]),
        ];
        frame.render_widget(
            Paragraph::new(empty_msg).alignment(Alignment::Center),
            inner,
        );
        return;
    }

    // U15 arithmetic: status(2) + proto(4) + time(10) + 3 inter-column gaps.
    let fixed_cols: u16 = 2 + 4 + 10 + 3;
    // Width budget available to the name cell before primary `*` reserve.
    let name_cell_width = inner.width.saturating_sub(fixed_cols) as usize;
    let items: Vec<Row> = app
        .runtime
        .profiles
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let is_selected = app.profile_list_state.selected() == Some(idx);
            let signal = signal_for(&snapshots, primary.as_ref(), &p.name);
            let is_never_used = p.last_used.is_none();

            // Status cell: U15 badge taxonomy + optional `!` risk annotation.
            // Numeric prefix (1..=9) remains the affordance for keyboard
            // quick-select; once a row is active the badge replaces the number
            // so the user sees state, not muscle-memory.
            let status_cell = if let Some((glyph, style)) = signal.badge {
                let mut spans = vec![Span::styled(glyph, style)];
                if signal.risk {
                    spans.push(Span::styled("!", Style::default().fg(theme::WARNING)));
                }
                Cell::from(Line::from(spans))
            } else if idx < 9 {
                Cell::from(Span::styled(
                    format!("{}", idx + 1),
                    Style::default().fg(theme::TEXT_SECONDARY),
                ))
            } else {
                Cell::from(Span::styled(" ", Style::default()))
            };

            // Primary marker: shown only when there's enough room for both a
            // 2-char ` *` suffix AND a 3-char minimum name stub. Below that we
            // suppress the marker (header still carries it cross-surface).
            let show_primary_marker =
                should_show_primary_marker(signal.is_primary, name_cell_width);
            let primary_reserve = if show_primary_marker { 2 } else { 0 };
            let name_budget = name_cell_width.saturating_sub(primary_reserve).max(1);

            let name_style = if is_selected && signal.is_active {
                Style::default()
                    .fg(signal.accent)
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default()
                    .fg(theme::ROW_SELECTED_FG)
                    .add_modifier(Modifier::BOLD)
            } else if signal.is_primary {
                Style::default()
                    .fg(signal.accent)
                    .add_modifier(Modifier::BOLD)
            } else if signal.is_active {
                Style::default().fg(signal.accent)
            } else if is_never_used {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(theme::INACTIVE)
            };

            let display_name = utils::truncate(&p.name, name_budget);
            let mut name_spans = vec![Span::styled(display_name, name_style)];
            if show_primary_marker {
                name_spans.push(Span::styled(
                    " *",
                    Style::default()
                        .fg(signal.accent)
                        .add_modifier(Modifier::BOLD),
                ));
            }
            let name_cell = Cell::from(Line::from(name_spans));

            let proto_icon = match p.protocol {
                crate::app::Protocol::WireGuard => "WG",
                crate::app::Protocol::OpenVPN => "OV",
            };
            let proto_color = if signal.is_active {
                signal.accent
            } else if is_selected {
                theme::ACCENT_PRIMARY
            } else {
                theme::TEXT_SECONDARY
            };

            let time_str = if let Some(last_used) = p.last_used {
                let relative = utils::format_relative_time(last_used);
                if !relative.ends_with("ago") && !relative.is_empty() {
                    format!("{relative} ago")
                } else {
                    relative
                }
            } else {
                "never".to_string()
            };

            let row_style = if is_selected {
                Style::default().bg(theme::ROW_SELECTED_BG)
            } else {
                Style::default()
            };

            let proto_cell = Cell::from(Span::styled(proto_icon, Style::default().fg(proto_color)));
            let time_cell =
                Cell::from(Span::styled(time_str, Style::default().fg(Color::DarkGray)));

            Row::new(vec![status_cell, name_cell, proto_cell, time_cell]).style(row_style)
        })
        .collect();

    let table = Table::new(
        items,
        [
            Constraint::Length(2),  // Status: badge glyph (+ optional `!`)
            Constraint::Min(3),     // Profile name (flex, with optional ` *`)
            Constraint::Length(4),  // Protocol (WG/OV)
            Constraint::Length(10), // Last used time
        ],
    );
    frame.render_stateful_widget(table, inner, &mut app.profile_list_state);

    // Scrollbar Logic
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

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
    //! U15 sidebar tests. Cover the badge taxonomy migration, primary `*`
    //! marker, `!` risk annotation for mode-mismatch (`AddressableSuppressed`),
    //! and the narrow-width fallback at the 24-char inner-width boundary.
    //! Stage A smoke tests for U6 (empty-state, row rendering) remain.
    use super::*;
    use crate::app::App;
    use crate::state::{Protocol, VpnProfile};
    use crate::vortix_core::cidr::Cidr;
    use crate::vortix_core::engine::registry::Role;
    use crate::vortix_core::engine::state::ConnectionHealth;
    use crate::vortix_core::profile::ProfileId;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;
    use std::time::SystemTime;
    use unicode_width::UnicodeWidthStr;

    fn make_profile(name: &str) -> VpnProfile {
        VpnProfile {
            name: name.to_string(),
            protocol: Protocol::WireGuard,
            location: String::new(),
            config_path: PathBuf::from(format!("/tmp/{name}.conf")),
            last_used: None,
        }
    }

    fn snap_connected(name: &str, role: Role) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: ProfileId::new(name),
            state: Connection::Connected {
                profile_id: ProfileId::new(name),
                since: SystemTime::now(),
                health: ConnectionHealth::default(),
                details: Box::default(),
            },
            role,
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        }
    }

    fn snap_connecting(name: &str) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: ProfileId::new(name),
            state: Connection::Connecting {
                profile_id: ProfileId::new(name),
                started_at: SystemTime::now(),
                attempt: 1,
                retry_budget_remaining: std::time::Duration::from_secs(30),
            },
            role: Role::AwaitingInput,
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        }
    }

    fn snap_reconnecting(name: &str) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: ProfileId::new(name),
            state: Connection::Reconnecting {
                profile_id: ProfileId::new(name),
                started_at: SystemTime::now(),
                attempt: 1,
                retry_budget_remaining: std::time::Duration::from_secs(30),
                last_error: None,
            },
            role: Role::Reconnecting {
                prior_role: Box::new(Role::Primary {
                    allowed_ips: vec![],
                }),
            },
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        }
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
    fn empty_registry_and_empty_profiles_renders_no_profiles_empty_state() {
        let mut app = App::new_test();
        assert_eq!(app.registry.tunnel_count(), 0);
        assert!(app.runtime.profiles.is_empty());

        let out = render_to_string(&mut app, 40, 10);
        assert!(
            out.contains("No profiles yet"),
            "expected empty-state copy, got:\n{out}"
        );
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
    fn empty_registry_yields_no_active_marker_for_any_profile() {
        let snapshots: Vec<TunnelSnapshot> = Vec::new();
        let sig = signal_for(&snapshots, None, "anything");
        assert!(!sig.is_active);
        assert!(sig.badge.is_none());
        assert!(!sig.is_primary);
        assert!(!sig.risk);
    }

    // ── U15 badge taxonomy ────────────────────────────────────────────────

    #[test]
    fn connected_snapshot_renders_filled_circle_glyph() {
        let snap = snap_connected(
            "vpn1",
            Role::Primary {
                allowed_ips: vec![],
            },
        );
        let (glyph, _) = status_badge_for(&snap).expect("connected → badge");
        assert_eq!(glyph, "●");
    }

    #[test]
    fn connecting_snapshot_renders_half_circle_glyph() {
        let snap = snap_connecting("vpn1");
        let (glyph, _) = status_badge_for(&snap).expect("connecting → badge");
        assert_eq!(glyph, "◐");
    }

    #[test]
    fn unauthoritative_connected_badge_renders_dim_grey() {
        // R4 of the state-authority contract: when a Connected tunnel's
        // iface can't be reliably attributed to its PID (current case:
        // externally-started OpenVPN on macOS where the scanner's
        // ifconfig-scan fallback collides across PIDs), the row's
        // status badge must visually distinguish from a fully-tracked
        // Connected tunnel.
        let mut snap = snap_connected(
            "vpn1",
            Role::Addressable {
                allowed_ips: vec![],
            },
        );
        if let Connection::Connected {
            ref mut details, ..
        } = snap.state
        {
            details.interface_authoritative = false;
        }
        let (glyph, style) = status_badge_for(&snap).expect("connected → badge");
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
            Some(theme::INACTIVE),
            "unauthoritative Connected must use the inactive color"
        );
    }

    #[test]
    fn authoritative_connected_badge_renders_bright_green_no_dim() {
        // Inverse check: a normal Connected tunnel (interface_authoritative
        // defaults to true) keeps the bright SUCCESS color and no DIM
        // modifier.
        let snap = snap_connected(
            "vpn1",
            Role::Primary {
                allowed_ips: vec![],
            },
        );
        let (glyph, style) = status_badge_for(&snap).expect("connected → badge");
        assert_eq!(glyph, "●");
        assert!(!style.add_modifier.contains(Modifier::DIM));
        assert_eq!(style.fg, Some(theme::SUCCESS));
    }

    #[test]
    fn reconnecting_snapshot_renders_reload_glyph_dim() {
        let snap = snap_reconnecting("vpn1");
        let (glyph, style) = status_badge_for(&snap).expect("reconnecting → badge");
        assert_eq!(glyph, "↻");
        assert!(
            style.add_modifier.contains(Modifier::DIM),
            "reconnecting must dim to distinguish from connecting under monochrome — got {style:?}"
        );
    }

    #[test]
    fn disconnected_no_failure_renders_no_badge() {
        let snap = TunnelSnapshot {
            profile_id: ProfileId::new("vpn1"),
            state: Connection::Disconnected { last_failure: None },
            role: Role::Addressable {
                allowed_ips: vec![],
            },
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        };
        assert!(status_badge_for(&snap).is_none());
    }

    #[test]
    fn disconnected_with_failure_renders_x_glyph_error() {
        use crate::vortix_core::engine::state::FailureReason;
        let snap = TunnelSnapshot {
            profile_id: ProfileId::new("vpn1"),
            state: Connection::Disconnected {
                last_failure: Some(FailureReason::HandshakeFailed("test".to_string())),
            },
            role: Role::Addressable {
                allowed_ips: vec![],
            },
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        };
        let (glyph, style) = status_badge_for(&snap).expect("failure → badge");
        assert_eq!(glyph, "✗");
        assert_eq!(style.fg, Some(theme::ERROR));
    }

    // ── U15 width discipline ──────────────────────────────────────────────

    #[test]
    fn unicode_width_of_reconnecting_glyph_is_one() {
        // Load-bearing for U15 fixed_cols arithmetic: if `↻` were width=2 the
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

    // ── U15 primary `*` marker ────────────────────────────────────────────

    #[test]
    fn primary_marker_shown_when_name_cell_width_is_five() {
        // inner.width=24, fixed_cols=19 → name_cell_width=5 → name_budget=3
        // after the 2-char reserve. This is the plan U15 boundary case
        // (line 971): "inner.width = 24 → name_budget = 3; primary `*`
        // rendered".
        assert!(should_show_primary_marker(true, 5));
    }

    #[test]
    fn primary_marker_hidden_when_name_cell_width_is_four() {
        // inner.width=23, fixed_cols=19 → name_cell_width=4 → name_budget=2
        // after the 2-char reserve. Plan U15 line 972: "inner.width = 23 →
        // name_budget = 2; primary `*` hidden".
        assert!(!should_show_primary_marker(true, 4));
    }

    #[test]
    fn primary_marker_hidden_when_not_primary() {
        // Even at generous widths, non-primary rows never carry the marker.
        assert!(!should_show_primary_marker(false, 80));
    }

    #[test]
    fn signal_for_marks_primary_when_id_matches() {
        let snap = snap_connected(
            "corp",
            Role::Primary {
                allowed_ips: vec![Cidr {
                    addr: "0.0.0.0".parse().unwrap(),
                    prefix_len: 0,
                }],
            },
        );
        let primary = ProfileId::new("corp");
        let sig = signal_for(std::slice::from_ref(&snap), Some(&primary), "corp");
        assert!(sig.is_primary);
        assert!(sig.is_active);
        assert_eq!(sig.badge.map(|(g, _)| g), Some("●"));
    }

    #[test]
    fn signal_for_does_not_mark_primary_for_other_rows() {
        let snap = snap_connected(
            "corp",
            Role::Primary {
                allowed_ips: vec![],
            },
        );
        let primary = ProfileId::new("corp");
        let sig = signal_for(std::slice::from_ref(&snap), Some(&primary), "other");
        assert!(!sig.is_primary);
        assert!(!sig.is_active);
    }

    // ── U15 risk annotation ───────────────────────────────────────────────

    #[test]
    fn addressable_suppressed_role_triggers_risk_annotation() {
        let snap = snap_connected(
            "vpn1",
            Role::AddressableSuppressed {
                allowed_ips: vec![Cidr {
                    addr: "0.0.0.0".parse().unwrap(),
                    prefix_len: 0,
                }],
            },
        );
        assert!(
            has_risk_annotation(&snap),
            "AddressableSuppressed role surfaces mode-mismatch `!` annotation"
        );
    }

    #[test]
    fn addressable_role_no_risk_annotation() {
        let snap = snap_connected(
            "vpn1",
            Role::Addressable {
                allowed_ips: vec![],
            },
        );
        assert!(!has_risk_annotation(&snap));
    }

    #[test]
    fn primary_role_no_risk_annotation() {
        let snap = snap_connected(
            "vpn1",
            Role::Primary {
                allowed_ips: vec![],
            },
        );
        assert!(!has_risk_annotation(&snap));
    }
}
