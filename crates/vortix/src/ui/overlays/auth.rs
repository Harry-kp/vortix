use crate::app::AuthField;
use crate::{constants, theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Auth-overlay layout.
///
/// Form-style rendering: each row has a focus marker, a fixed-width label
/// column, and an aligned value column so the eye scans down a single
/// column instead of zig-zagging across stacked label/input pairs. The
/// focus indicator (▸) is the only per-row marker that moves; the cursor
/// block sits inline with the value. Static-challenge profiles add a
/// third row whose label comes from the .ovpn directive verbatim.
///
/// ```text
/// ┌─ Authenticate ───────────────────────────────────┐
/// │                                                  │
/// │   ovpn-totp · OpenVPN                            │
/// │                                                  │
/// │   ▸ Username        vortix▌                      │
/// │     Password        ●●●●●●●●●●●                  │
/// │     Enter TOTP      ●●●●●●                       │
/// │                                                  │
/// │     [x] Save credentials for future sessions     │
/// └──────────────────────────────────────────────────┘
/// ```
// ── Label column width: keep alignment stable across all rows. ──
//
// 11 chars accommodates "Password" (8), "Username" (8), and most
// common static-challenge prompts ("Enter TOTP", "TOTP code",
// "PIN code", "Verification"). Longer prompts truncate at the
// column boundary so the value column stays aligned with the
// shorter rows -- the full prompt remains visible in the .ovpn
// file and the user already saw it when configuring the profile.
const LABEL_WIDTH: usize = 11;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn render(
    frame: &mut Frame,
    profile_name: &str,
    username: &str,
    username_cursor: usize,
    password: &str,
    password_cursor: usize,
    otp: &str,
    otp_cursor: usize,
    focused_field: &AuthField,
    save_credentials: bool,
    connect_after: bool,
    static_challenge_prompt: Option<&str>,
) {
    let has_otp_field = static_challenge_prompt.is_some();
    let area = frame.area();

    // Vertical: center the popup with ~50% of screen height. Horizontal:
    // fixed ~58 cells wide, centered. The fixed width keeps the label-
    // value column alignment stable at any terminal width >= 60 cols.
    let popup_height: u16 = if has_otp_field { 14 } else { 12 };
    let popup_width: u16 = 60.min(area.width.saturating_sub(4));

    let popup_layout = Layout::vertical([
        Constraint::Length(area.height.saturating_sub(popup_height) / 2),
        Constraint::Length(popup_height),
        Constraint::Min(1),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Length(area.width.saturating_sub(popup_width) / 2),
        Constraint::Length(popup_width),
        Constraint::Min(1),
    ])
    .split(popup_layout[1])[1];

    frame.render_widget(Clear, popup_area);

    let (title, footer) = if connect_after {
        (constants::TITLE_AUTH_PROMPT, constants::TITLE_AUTH_FOOTER)
    } else {
        (
            constants::TITLE_AUTH_MANAGE,
            constants::TITLE_AUTH_MANAGE_FOOTER,
        )
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::ACCENT_PRIMARY))
        .title(format!(" {title} "))
        .title_bottom(Line::from(format!(" {footer} ")).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // ── Per-row builder ──────────────────────────────────────────────
    //
    // Row format: `  <focus-marker> <label, fixed-width> <value-with-cursor>`
    //   - focus marker: '▸' on the focused row, ' ' otherwise
    //   - label: left-justified in LABEL_WIDTH cells
    //   - value: masked password / OTP renders as filled-circle dots;
    //     cursor block sits inline; non-focused rows show muted text
    //     without a blinking cursor
    let row =
        |label: &str, value: &str, cursor: usize, mask: bool, focused: bool| -> Line<'static> {
            let display_text: String = if mask {
                "\u{25CF}".repeat(value.chars().count())
            } else {
                value.to_string()
            };

            let marker = if focused { "\u{25B8}" } else { " " }; // ▸

            let label_style = if focused {
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            };

            // Truncate over-long labels to keep the value column aligned;
            // pad shorter labels with spaces. Both arms always produce
            // exactly LABEL_WIDTH visible chars.
            let label_text: String = {
                let count = label.chars().count();
                if count > LABEL_WIDTH {
                    label.chars().take(LABEL_WIDTH).collect()
                } else {
                    let mut s = label.to_string();
                    s.push_str(&" ".repeat(LABEL_WIDTH - count));
                    s
                }
            };

            let mut spans: Vec<Span<'static>> = vec![
                Span::styled(
                    format!("   {marker} "),
                    Style::default().fg(theme::ACCENT_PRIMARY),
                ),
                Span::styled(label_text, label_style),
                Span::raw("  "),
            ];

            if focused {
                // Split the displayed value around the cursor position so
                // the cursor block falls between the right characters when
                // the user moves left/right inside the field.
                let before: String = display_text.chars().take(cursor).collect();
                let cursor_char: String = display_text
                    .chars()
                    .nth(cursor)
                    .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string()); // █
                let after: String = display_text.chars().skip(cursor + 1).collect();
                spans.push(Span::styled(
                    before,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ));
                spans.push(Span::styled(
                    cursor_char,
                    Style::default()
                        .fg(theme::ACCENT_SECONDARY)
                        .add_modifier(Modifier::REVERSED)
                        .add_modifier(Modifier::SLOW_BLINK),
                ));
                spans.push(Span::styled(
                    after,
                    Style::default().fg(theme::TEXT_PRIMARY),
                ));
            } else {
                // Non-focused rows: show the value muted; empty values
                // render an em-dash placeholder so the row never looks
                // visually broken on first paint.
                let shown = if display_text.is_empty() {
                    "\u{2014}".to_string() // —
                } else {
                    display_text
                };
                spans.push(Span::styled(shown, Style::default().fg(theme::INACTIVE)));
            }
            Line::from(spans)
        };

    // ── Build the body ──
    let mut text: Vec<Line> = Vec::with_capacity(if has_otp_field { 12 } else { 10 });

    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::raw("   "),
        Span::styled(
            profile_name.to_string(),
            Style::default()
                .fg(theme::ACCENT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(theme::INACTIVE)),
        Span::styled("OpenVPN", Style::default().fg(theme::TEXT_SECONDARY)),
    ]));
    text.push(Line::from(""));

    text.push(row(
        "Username",
        username,
        username_cursor,
        false,
        *focused_field == AuthField::Username,
    ));
    text.push(row(
        "Password",
        password,
        password_cursor,
        true,
        *focused_field == AuthField::Password,
    ));
    if let Some(prompt) = static_challenge_prompt {
        text.push(row(
            prompt,
            otp,
            otp_cursor,
            true,
            *focused_field == AuthField::Otp,
        ));
    }
    text.push(Line::from(""));

    // ── Checkbox row ──────────────────────────────────────────────────
    let checkbox_focused = *focused_field == AuthField::SaveCheckbox;
    let checkbox_icon = if save_credentials {
        "\u{2611}" // ☑
    } else {
        "\u{2610}" // ☐
    };
    let (marker, marker_style) = if checkbox_focused {
        ("\u{25B8}", Style::default().fg(theme::ACCENT_PRIMARY))
    } else {
        (" ", Style::default().fg(theme::ACCENT_PRIMARY))
    };
    let checkbox_style = if checkbox_focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    text.push(Line::from(vec![
        Span::styled(format!("   {marker} "), marker_style),
        Span::styled(format!("{checkbox_icon}  "), checkbox_style),
        Span::styled("Save credentials for future sessions", checkbox_style),
    ]));

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}
