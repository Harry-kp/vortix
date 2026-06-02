use crate::app::AuthField;
use crate::{constants, theme};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

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
    let popup_layout = Layout::vertical([
        Constraint::Percentage(25),
        Constraint::Percentage(50),
        Constraint::Percentage(25),
    ])
    .split(area);

    let popup_area = Layout::horizontal([
        Constraint::Percentage(20),
        Constraint::Percentage(60),
        Constraint::Percentage(20),
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
        .title(title)
        .title_bottom(Line::from(footer).centered());

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build text cursor helper
    let make_cursor_line =
        |text: &str, cursor: usize, is_focused: bool, mask: bool| -> Line<'static> {
            let display_text: String = if mask {
                "\u{25CF}".repeat(text.chars().count())
            } else {
                text.to_string()
            };

            let before: String = display_text.chars().take(cursor).collect();
            let cursor_char: String = display_text
                .chars()
                .nth(cursor)
                .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string()); // █
            let after: String = display_text.chars().skip(cursor + 1).collect();

            let prompt_style = if is_focused {
                Style::default().fg(theme::ACCENT_PRIMARY)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            };

            if is_focused {
                Line::from(vec![
                    Span::styled(" > ", prompt_style),
                    Span::styled(before, Style::default().fg(theme::TEXT_PRIMARY)),
                    Span::styled(
                        cursor_char,
                        Style::default()
                            .fg(theme::ACCENT_SECONDARY)
                            .add_modifier(Modifier::REVERSED)
                            .add_modifier(Modifier::SLOW_BLINK),
                    ),
                    Span::styled(after, Style::default().fg(theme::TEXT_PRIMARY)),
                ])
            } else {
                let full_text: String = if mask && !text.is_empty() {
                    "\u{25CF}".repeat(text.chars().count())
                } else if text.is_empty() {
                    String::new()
                } else {
                    text.to_string()
                };
                Line::from(vec![
                    Span::styled("   ", prompt_style),
                    Span::styled(full_text, Style::default().fg(theme::INACTIVE)),
                ])
            }
        };

    // Checkbox display
    let checkbox_focused = *focused_field == AuthField::SaveCheckbox;
    let checkbox_icon = if save_credentials { "[x]" } else { "[ ]" };
    let checkbox_style = if checkbox_focused {
        Style::default()
            .fg(theme::ACCENT_PRIMARY)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };
    let checkbox_label_style = if checkbox_focused {
        Style::default().fg(theme::TEXT_PRIMARY)
    } else {
        Style::default().fg(theme::TEXT_SECONDARY)
    };

    // Layout budget: today's two-field overlay fits at 80x24 by allocating
    // a blank row between each labelled field. With the third (OTP) field
    // we drop the inter-field blanks (Username/Password/OTP packed) so the
    // overlay still fits inside the 50% vertical allocation — plan
    // 2026-06-02-001 U3 / PF-5. The non-MFA path is byte-identical to today.
    let mut text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Profile: ", Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(
                profile_name.to_string(),
                Style::default()
                    .fg(theme::ACCENT_PRIMARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" (OpenVPN)", Style::default().fg(theme::TEXT_SECONDARY)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Username:",
            if *focused_field == AuthField::Username {
                Style::default()
                    .fg(theme::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            },
        )),
        make_cursor_line(
            username,
            username_cursor,
            *focused_field == AuthField::Username,
            false,
        ),
    ];
    if !has_otp_field {
        text.push(Line::from(""));
    }
    text.push(Line::from(Span::styled(
        "  Password:",
        if *focused_field == AuthField::Password {
            Style::default()
                .fg(theme::TEXT_PRIMARY)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::TEXT_SECONDARY)
        },
    )));
    text.push(make_cursor_line(
        password,
        password_cursor,
        *focused_field == AuthField::Password,
        true,
    ));
    if let Some(prompt) = static_challenge_prompt {
        // The prompt comes from the user's .ovpn config and is rendered
        // verbatim. OTP input is ALWAYS masked regardless of the echo
        // flag (plan 2026-06-02-001 DEC-2) — echo=1 means the server
        // permits display, not that vortix must show.
        text.push(Line::from(Span::styled(
            format!("  {prompt}:"),
            if *focused_field == AuthField::Otp {
                Style::default()
                    .fg(theme::TEXT_PRIMARY)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_SECONDARY)
            },
        )));
        text.push(make_cursor_line(
            otp,
            otp_cursor,
            *focused_field == AuthField::Otp,
            true,
        ));
    }
    text.push(Line::from(""));
    text.push(Line::from(vec![
        Span::styled(format!("  {checkbox_icon} "), checkbox_style),
        Span::styled("Save credentials for future sessions", checkbox_label_style),
    ]));

    frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
}
