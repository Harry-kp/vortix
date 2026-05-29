//! Auto-promote banner overlay (plan 001 U19, D-3).
//!
//! Renders when `App.auto_promote_banner` is `Some(_)` — set by the
//! registry's `PrimaryTunnelChanged{ reason: PriorPrimaryDisconnected }`
//! event when a 0/0 secondary takes over after the prior primary
//! disconnects. The banner stays visible for
//! [`AUTO_PROMOTE_REVERT_WINDOW_SECS`] (10s by default) and is
//! auto-dismissed by the App tick loop. While visible, the `[u]`
//! key fires `Message::RevertAutoPromote` (wired in
//! `app/input.rs`).
//!
//! Why a top-center anchored banner instead of a top-right toast:
//! this is a one-off contextual notice for a novel keybinding, not
//! a routine log message. The user needs to see the `[u]` shortcut
//! prominently to act inside the 10s window. Centered + countdown
//! signals "decision pending"; the top-right toast slot stays
//! reserved for routine errors / status that don't gate user action.

use crate::app::App;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Render the auto-promote banner if one is active and unexpired.
pub fn render(frame: &mut Frame, app: &App) {
    let Some(banner) = &app.auto_promote_banner else {
        return;
    };
    if banner.is_expired() {
        return;
    }

    let area = frame.area();
    // Top-center anchored. Wide enough for the longest line; clamps
    // to viewport width on small terminals.
    let width = 64.min(area.width.saturating_sub(2));
    let height = 5;
    let x = (area.width / 2).saturating_sub(width / 2);
    let banner_area = Rect {
        x,
        y: 1,
        width,
        height,
    };

    frame.render_widget(Clear, banner_area);

    let theme = crate::theme::current();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.toast_warning))
        .title(Span::styled(
            " Primary auto-promoted ",
            Style::default()
                .fg(Color::Black)
                .bg(theme.toast_warning)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(banner_area);
    frame.render_widget(block, banner_area);

    let remaining_secs = banner
        .expires
        .saturating_duration_since(std::time::Instant::now())
        .as_secs();

    let lines = vec![
        Line::from(vec![
            Span::styled("'", Style::default().fg(crate::theme::TEXT_SECONDARY)),
            Span::styled(
                banner.to.as_str().to_string(),
                Style::default()
                    .fg(crate::theme::SUCCESS)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "' is now the active exit — '",
                Style::default().fg(crate::theme::TEXT_SECONDARY),
            ),
            Span::styled(
                banner.from.as_str().to_string(),
                Style::default()
                    .fg(crate::theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "' dropped.",
                Style::default().fg(crate::theme::TEXT_SECONDARY),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "[u] ",
                Style::default()
                    .fg(theme.toast_warning)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Revert (reconnect '",
                Style::default().fg(crate::theme::TEXT_SECONDARY),
            ),
            Span::styled(
                banner.from.as_str().to_string(),
                Style::default().fg(crate::theme::ACCENT_PRIMARY),
            ),
            Span::styled(
                format!("') · auto-dismiss in {remaining_secs}s",),
                Style::default().fg(crate::theme::TEXT_SECONDARY),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(lines).alignment(Alignment::Center);
    frame.render_widget(paragraph, inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_core::profile::ProfileId;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| render(frame, app)).expect("draw");
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
    fn no_banner_means_empty_render() {
        // When `auto_promote_banner` is None, render must be a no-op
        // — leave the underlying dashboard untouched.
        let app = App::new_test();
        assert!(app.auto_promote_banner.is_none(), "setup precondition");
        let out = render_to_string(&app, 80, 24);
        // Empty-render leaves the terminal cells as spaces; no
        // banner text should appear.
        assert!(
            !out.contains("auto-promoted"),
            "no banner text should render when state is None:\n{out}"
        );
        assert!(
            !out.contains("[u]"),
            "no [u] hint when state is None:\n{out}"
        );
    }

    #[test]
    fn active_banner_renders_both_profile_names_and_u_hint() {
        // Regression: this is the gap the audit caught — state was
        // set but never rendered. Assert the render path exists and
        // produces both profile names + the `[u]` revert hint.
        let mut app = App::new_test();
        app.auto_promote_banner = Some(crate::state::AutoPromoteBanner::new(
            ProfileId::new("corp"),
            ProfileId::new("lab"),
        ));
        let out = render_to_string(&app, 80, 24);

        assert!(
            out.contains("corp"),
            "banner must surface the dropped (from) profile name:\n{out}"
        );
        assert!(
            out.contains("lab"),
            "banner must surface the promoted (to) profile name:\n{out}"
        );
        assert!(
            out.contains("[u]"),
            "banner must expose the [u] revert keybinding:\n{out}"
        );
        assert!(
            out.contains("auto-promoted"),
            "banner must include the title 'Primary auto-promoted':\n{out}"
        );
    }

    #[test]
    fn expired_banner_does_not_render() {
        // The tick loop is supposed to clear expired banners, but
        // defensive: if the state lingers a tick longer than it
        // should, the render path itself bails on expiry.
        let mut app = App::new_test();
        let mut banner =
            crate::state::AutoPromoteBanner::new(ProfileId::new("corp"), ProfileId::new("lab"));
        banner.expires = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("Instant::now() can subtract 1s on every test runner");
        app.auto_promote_banner = Some(banner);

        let out = render_to_string(&app, 80, 24);
        assert!(
            !out.contains("auto-promoted"),
            "expired banner must not render:\n{out}"
        );
    }
}
