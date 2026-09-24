//! UI overlay modules

pub mod action_menu {
    //! Action Menu overlay for context-sensitive actions.
    //!
    //! Provides a lazydocker-style popup menu triggered by 'x'.

    use crate::message::ActionMenuItem;
    use crate::ui::helpers::centered_rect_fixed;
    use crate::ui::theme;
    use ratatui::{
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, List, ListItem, ListState},
        Frame,
    };

    /// Render the action menu overlay
    #[allow(clippy::cast_possible_truncation)]
    pub fn render(
        frame: &mut Frame,
        items: &[ActionMenuItem],
        list_state: &mut ListState,
        title: &str,
    ) {
        // Calculate menu dimensions based on content
        let max_label_len = items.iter().map(|i| i.label.len()).max().unwrap_or(20);
        let max_key_len = items.iter().map(|i| i.key.len()).max().unwrap_or(1);
        let menu_width = (max_key_len + max_label_len + 8).min(60) as u16; // key + padding + label
        let menu_height = (items.len().max(1) + 2).min(18) as u16; // items + borders

        let area = centered_rect_fixed(menu_width, menu_height, frame.area());

        // Clear background
        crate::ui::helpers::clear_area(frame, area);

        // Build the block
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().border_focused))
            .title(format!(" {title} "));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Build list items
        let list_items: Vec<ListItem> = if items.is_empty() {
            vec![ListItem::new(Line::from(vec![Span::styled(
                " No actions available ",
                Style::default().fg(theme::current().nord_polar_night_4),
            )]))]
        } else {
            items
                .iter()
                .map(|item| {
                    let line = Line::from(vec![
                        Span::styled(
                            format!(" {} ", item.key),
                            Style::default()
                                .fg(theme::current().accent_primary)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            item.label,
                            Style::default().fg(theme::current().text_primary),
                        ),
                    ]);
                    ListItem::new(line)
                })
                .collect()
        };

        let list = List::new(list_items);

        if items.is_empty() {
            frame.render_widget(list, inner);
        } else {
            let list = list
                .highlight_style(
                    Style::default()
                        .bg(theme::current().row_selected_bg)
                        .fg(theme::current().row_selected_fg)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("▶ ");
            frame.render_stateful_widget(list, inner, list_state);
        }
    }
}
pub mod auth {
    use crate::app::AuthField;
    use crate::{constants, ui::theme};
    use ratatui::{
        layout::{Alignment, Constraint, Layout},
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
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
        reveal_secrets: bool,
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

        crate::ui::helpers::clear_area(frame, popup_area);

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
            .border_style(Style::default().fg(theme::current().accent_primary))
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
                        .fg(theme::current().accent_primary)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme::current().text_secondary)
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
                        Style::default().fg(theme::current().accent_primary),
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
                    spans.extend(crate::ui::helpers::text_entry_spans(
                        before,
                        cursor_char,
                        after,
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
                    spans.push(Span::styled(
                        shown,
                        Style::default().fg(theme::current().inactive),
                    ));
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
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ·  ", Style::default().fg(theme::current().inactive)),
            Span::styled(
                "OpenVPN",
                Style::default().fg(theme::current().text_secondary),
            ),
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
            !reveal_secrets,
            *focused_field == AuthField::Password,
        ));
        if let Some(prompt) = static_challenge_prompt {
            text.push(row(
                prompt,
                otp,
                otp_cursor,
                !reveal_secrets,
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
            (
                "\u{25B8}",
                Style::default().fg(theme::current().accent_primary),
            )
        } else {
            (" ", Style::default().fg(theme::current().accent_primary))
        };
        let checkbox_style = if checkbox_focused {
            Style::default()
                .fg(theme::current().accent_primary)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::current().text_secondary)
        };
        text.push(Line::from(vec![
            Span::styled(format!("   {marker} "), marker_style),
            Span::styled(format!("{checkbox_icon}  "), checkbox_style),
            Span::styled("Save credentials for future sessions", checkbox_style),
        ]));

        frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
    }
}
pub mod config_viewer {
    //! Config file viewer overlay

    use crate::app::App;
    use crate::ui::helpers::centered_rect;
    use crate::ui::theme;
    use ratatui::{
        layout::{Constraint, Layout, Rect},
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
        Frame,
    };
    use std::path::PathBuf;

    /// Render config file viewer overlay
    pub fn render(frame: &mut Frame, app: &App) {
        let area = centered_rect(85, 85, frame.area());

        // Clear the background
        crate::ui::helpers::clear_area(frame, area);

        // Read directly from the cached view; if the user opened the viewer
        // with no profile selected (or read failed in OpenConfig and stashed
        // an error string), the cache holds the right body to display.
        let (profile_name, config_path): (String, PathBuf) =
            if let Some(idx) = app.profile_list_state.selected() {
                if let Some(profile) = app.runtime.profiles.get(idx) {
                    (profile.name.clone(), profile.config_path.clone())
                } else {
                    (String::new(), PathBuf::new())
                }
            } else {
                (String::new(), PathBuf::new())
            };

        let title = if profile_name.is_empty() {
            " Config Viewer ".to_string()
        } else {
            let max_name = (area.width as usize).saturating_sub(14); // " " + " - Config " + borders
            let short = crate::ui::helpers::truncate_to_width(&profile_name, max_name);
            format!(" {short} - Config ")
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().border_focused))
            .title(title)
            .title_bottom(Line::from(" [Esc] Close  [↑/↓] Scroll ").centered());

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Show the file path at the top
        let path_style = Style::default().fg(theme::current().key_hint_desc);

        // Lines + count come straight from the cache built in `OpenConfig`.
        // No file re-read, no per-line re-highlighting per frame.
        let (lines, total_lines): (Vec<Line<'static>>, usize) = match app.cached_config.as_ref() {
            Some(cached) => (
                cached.highlighted_lines.clone(),
                cached.highlighted_lines.len(),
            ),
            None => (vec![highlight_config_line("No config loaded")], 1),
        };
        let paragraph = Paragraph::new(lines)
            .style(Style::default().fg(theme::current().text_primary))
            .scroll((app.config_scroll, 0));

        // Add path hint at bottom
        let content_area = Layout::vertical([
            Constraint::Length(1), // Path
            Constraint::Min(1),    // Content
        ])
        .split(inner);

        // Render path with scroll indicator
        let path_display = config_path.display().to_string();
        let scroll_info = format!(" (line {}/{})", app.config_scroll + 1, total_lines.max(1));
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Path: ", path_style),
                Span::styled(
                    path_display,
                    Style::default().fg(theme::current().text_secondary),
                ),
                Span::styled(
                    scroll_info,
                    Style::default().fg(theme::current().key_hint_desc),
                ),
            ])),
            content_area[0],
        );

        // Render content
        frame.render_widget(paragraph, content_area[1]);

        // Scrollbar Logic
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"))
            .style(Style::default().fg(theme::current().nord_polar_night_4))
            .thumb_style(Style::default().fg(theme::current().accent_primary));

        let mut scrollbar_state =
            ScrollbarState::new(total_lines.saturating_sub(content_area[1].height as usize))
                .position(app.config_scroll as usize);

        // Scrollbar on the right border
        let scroll_area = Rect {
            x: area.right().saturating_sub(1),
            y: content_area[1].y,
            width: 1,
            height: content_area[1].height,
        };

        frame.render_stateful_widget(scrollbar, scroll_area, &mut scrollbar_state);
    }

    /// Apply syntax highlighting to config lines.
    ///
    /// Exposed `pub(crate)` so the App's open-config handler can build a
    /// pre-highlighted cache of the entire file once, and the renderer just
    /// clones the cached Vec each frame instead of re-running this function
    /// (and its sub-allocations) for every visible line on every keystroke.
    pub(crate) fn highlight_config_line(line: &str) -> Line<'static> {
        let line = line.to_string();
        let trimmed = line.trim();

        // Comments
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            return Line::from(Span::styled(
                line,
                Style::default().fg(theme::current().inactive),
            ));
        }

        // Section headers [Interface], [Peer], etc.
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return Line::from(Span::styled(
                line,
                Style::default()
                    .fg(theme::current().yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        // Key = Value pairs
        if let Some(eq_pos) = line.find('=') {
            let (key, rest) = line.split_at(eq_pos);
            let value = &rest[1..]; // Skip the '='

            // Mask sensitive values
            let masked_value = mask_sensitive_value(key.trim(), value.trim());

            return Line::from(vec![
                Span::styled(
                    key.to_string(),
                    Style::default().fg(theme::current().accent_primary),
                ),
                Span::styled("=", Style::default().fg(theme::current().separator)),
                Span::styled(
                    masked_value,
                    Style::default().fg(theme::current().text_primary),
                ),
            ]);
        }

        // OpenVPN directives (single words or with args)
        if !trimmed.is_empty() {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let directive = parts[0];

            // Known OpenVPN directives
            let known_directives = [
                "client",
                "dev",
                "proto",
                "remote",
                "resolv-retry",
                "nobind",
                "persist-key",
                "persist-tun",
                "ca",
                "cert",
                "key",
                "cipher",
                "auth",
                "verb",
                "tls-client",
                "remote-cert-tls",
                "auth-user-pass",
                "comp-lzo",
                "route",
                "redirect-gateway",
                "dhcp-option",
            ];

            if known_directives.contains(&directive.to_lowercase().as_str()) {
                if parts.len() > 1 {
                    return Line::from(vec![
                        Span::styled(
                            directive.to_string(),
                            Style::default().fg(theme::current().accent_primary),
                        ),
                        Span::styled(" ", Style::default()),
                        Span::styled(
                            parts[1].to_string(),
                            Style::default().fg(theme::current().text_primary),
                        ),
                    ]);
                }
                return Line::from(Span::styled(
                    line,
                    Style::default().fg(theme::current().accent_primary),
                ));
            }
        }

        // Default: just return the line
        Line::from(Span::styled(
            line,
            Style::default().fg(theme::current().text_primary),
        ))
    }

    /// Mask sensitive values like private keys
    fn mask_sensitive_value(key: &str, value: &str) -> String {
        let sensitive_keys = ["privatekey", "presharedkey", "password", "secret"];

        let key_lower = key.to_lowercase();
        if sensitive_keys.iter().any(|k| key_lower.contains(k)) {
            // Show first 4 and last 4 chars, mask the rest
            let chars: Vec<char> = value.chars().collect();
            if chars.len() > 12 {
                let head: String = chars[..4].iter().collect();
                let tail: String = chars[chars.len() - 4..].iter().collect();
                format!("{head}...{tail} (masked)")
            } else {
                "••••••••••••".to_string()
            }
        } else {
            value.to_string()
        }
    }
}
pub mod confirm_dialog {
    //! Reusable confirmation dialog overlay.

    use crate::ui::theme;
    use ratatui::{
        layout::Rect,
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
        Frame,
    };

    /// Everything that varies between confirmation dialogs.
    pub struct ConfirmDialogConfig<'a> {
        pub title: &'a str,
        pub body: Vec<Line<'a>>,
        pub border_color: Color,
        pub confirm_selected: bool,
        pub confirm_label: &'a str,
        pub width: u16,
        pub height: u16,
    }

    /// Render a centered confirmation dialog with an action and Cancel choice.
    pub fn render(frame: &mut Frame, config: ConfirmDialogConfig) {
        let area = frame.area();
        let width = config.width.min(area.width.saturating_sub(4));
        let height = config.height.min(area.height.saturating_sub(2));
        let overlay = Rect {
            x: (area.width / 2).saturating_sub(width / 2),
            y: (area.height / 2).saturating_sub(height / 2),
            width,
            height,
        };

        crate::ui::helpers::clear_area(frame, overlay);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(config.border_color))
            .title(Span::styled(
                config.title,
                Style::default()
                    .fg(config.border_color)
                    .add_modifier(Modifier::BOLD),
            ));

        let inner = block.inner(overlay);
        frame.render_widget(block, overlay);

        let yes_style = if config.confirm_selected {
            Style::default()
                .fg(theme::current().text_dark)
                .bg(config.border_color)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::current().text_secondary)
        };
        let no_style = if config.confirm_selected {
            Style::default().fg(theme::current().text_secondary)
        } else {
            Style::default()
                .fg(theme::current().text_dark)
                .bg(theme::current().accent_primary)
                .add_modifier(Modifier::BOLD)
        };

        let yes_label = format!(
            "{}[Y] {} ",
            if config.confirm_selected {
                "▸ "
            } else {
                "  "
            },
            config.confirm_label
        );
        let no_label = format!(
            "{}[N] {} ",
            if config.confirm_selected {
                "  "
            } else {
                "▸ "
            },
            "Cancel"
        );

        let mut lines = config.body;
        lines.push(Line::from(""));
        lines.push(
            Line::from(vec![
                Span::styled(yes_label, yes_style),
                Span::styled("  ", Style::default()),
                Span::styled(no_label, no_style),
            ])
            .centered(),
        );

        frame.render_widget(Paragraph::new(lines), inner);
    }
}
pub mod help {
    //! Help overlay with four tabs: Keys, Roles, Sigils, Guard.
    //!
    //! `?` opens the overlay on the Keys tab. `Tab` / `Shift+Tab` cycle
    //! through the tabs (browser-style strip rendered at the top with the
    //! active tab highlighted). `j`/`k`/arrows scroll within the active
    //! tab; `Esc` or `?` close.
    //!
    //! Each tab gets a layout appropriate to its content density:
    //!
    //! - **Keys** — compact two-column reference (key + short action).
    //!   Many entries, short on either side.
    //! - **Roles** — card-style with multi-line prose. Few entries, each
    //!   needs ~3-5 lines of plain-English explanation. Same vocabulary
    //!   as `connection_details::role_line`.
    //! - **Sigils** — 3-column grid (glyph in its TUI color │ short label
    //!   │ one-line description). Reads from
    //!   [`crate::ui::sigils::CATALOG`] — the single source of truth that
    //!   the actual renderers also use. Drift between what users see
    //!   on-screen and what the help shows is structurally impossible.
    //! - **Guard** — card-style explainer for the Security Guard panel:
    //!   the three headline states (EXPOSED / PARTIAL / PROTECTED) and
    //!   what each row (IP, DNS, Encryption) actually
    //!   checks. Complements the Sigils tab — sigils explain the glyphs,
    //!   Guard explains the semantics.

    use crate::app::{state, state::HelpTab};
    use crate::ui::sigils::{Sigil, SigilCategory, CATALOG};
    use crate::ui::theme;
    use ratatui::{
        layout::{Constraint, Direction, Layout, Rect},
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph, Tabs, Wrap},
        Frame,
    };

    // ────────────────────────────── Keys tab ───────────────────────────────

    const HELP_TEXT: &[(&str, &[(&str, &str)])] = &[
        (
            "Global",
            &[
                ("1-9", "Quick connect to profile N"),
                ("d", "Disconnect focused tunnel / Cancel"),
                ("D", "Disconnect ALL active tunnels (when N>1)"),
                ("r", "Reconnect"),
                ("i", "Import profile (file, dir, URL)"),
                ("K", "Cycle kill switch mode"),
                ("y", "Copy VPN IP to clipboard"),
                ("Tab/S-Tab", "Next / Previous panel"),
                ("F1-F5", "Jump to panel (Prof/Det/Chart/Sec/Log)"),
                ("z", "Zoom focused panel"),
                ("x", "Action menu"),
                ("b", "Bulk action menu"),
                ("p", "Switch color theme"),
                ("/", "Search profiles"),
                ("?", "Toggle this help"),
                ("q", "Quit"),
            ],
        ),
        (
            "Sidebar (Profiles)",
            &[
                ("j / ↓", "Next profile"),
                ("k / ↑", "Previous profile"),
                ("g / Home", "First profile"),
                ("G / End", "Last profile"),
                ("PgUp/PgDn", "Page up / down"),
                ("c / Enter", "Connect / disconnect focused row"),
                ("R", "Rename profile"),
                ("v", "View config"),
                ("s", "Cycle sort order"),
                ("a", "Manage auth (OpenVPN)"),
                ("A", "Clear saved auth"),
                ("Del", "Delete profile"),
            ],
        ),
        (
            "Connection Details",
            &[
                ("c", "Cancel in-flight connect"),
                (
                    "(switch tunnels)",
                    "Use the sidebar (j/k) — Details follows the selected profile",
                ),
            ],
        ),
        (
            "Switch-VPN overlay",
            &[
                ("Y / Enter", "Switch — disconnect current, then connect new"),
                ("B", "Connect both — new becomes active exit"),
                ("N / Esc", "Cancel"),
            ],
        ),
        (
            "Logs Panel",
            &[
                ("j / ↓", "Scroll down"),
                ("k / ↑", "Scroll up"),
                ("f", "Cycle log level filter"),
                ("L", "Clear logs"),
            ],
        ),
        (
            "Config Viewer",
            &[
                ("j / ↓ / k / ↑", "Scroll"),
                ("g / G", "Top / Bottom"),
                ("Esc", "Close"),
            ],
        ),
        (
            "Help overlay",
            &[
                ("Tab", "Next tab (Keys → Roles → Sigils → Guard)"),
                ("Shift+Tab", "Previous tab"),
                ("j / k / ↑ / ↓", "Scroll within tab"),
                ("g / G", "Top / Bottom of tab"),
                ("? / Esc / q", "Close help"),
            ],
        ),
    ];

    // ────────────────────────────── Roles tab ───────────────────────────────

    /// `(label, description_paragraph)` for every Role label that
    /// `connection_details::role_line` can emit. Descriptions wrap inside
    /// the overlay so paragraph length is unlimited.
    const ROLE_GLOSSARY: &[(&str, &str)] = &[
    (
        "Primary",
        "Your active exit. Internet traffic flows through this tunnel — the kernel routes its default route here, so any new outbound connection goes via this tunnel's server.",
    ),
    (
        "Primary (10.0.0.0/8)",
        "Same as Primary, with the declared subnet shown in parens. Don't read this as 'only routes that subnet' — it IS the exit; the CIDR is just what the profile config declares.",
    ),
    (
        "Primary (multi)",
        "Same as Primary; the profile declares multiple subnets. Shown when the config has more than one declared CIDR (rare but possible).",
    ),
    (
        "Split tunnel",
        "Connected but NOT your exit. Only carries the routes the profile declared (its AllowedIPs for WireGuard, or `route` directives for OpenVPN). Internet traffic still uses your normal connection. Example: a corporate VPN routing only 10.0.0.0/8 so you can reach internal services without your browsing going through work.",
    ),
    (
        "Split tunnel (10.0.0.0/8)",
        "Same; the listed CIDR is the only subnet this tunnel routes. Everything else goes via your normal internet.",
    ),
    (
        "Split tunnel (multi)",
        "Same; the profile declares multiple non-default subnets.",
    ),
    (
        "Split tunnel (yielded)",
        "Wanted to be your exit (declared 0.0.0.0/0) but another tunnel won the race. 'Yielded' = stood down. Sits as a hot standby: if the active primary drops, the kernel re-routes through this tunnel and you'll see a toast naming the new active exit. You see this label after pressing Shift+B (Both) on the takeover overlay.",
    ),
    (
        "Split tunnel (multi, yielded)",
        "Same as yielded; the profile declares multiple subnets including 0/0. Another tunnel is the active exit; this one is a hot standby.",
    ),
    (
        "(external) suffix",
        "Tunnel detected as up but started outside vortix (e.g., `sudo openvpn ...` from another terminal) AND on a platform where vortix can't reliably attribute its kernel interface to its PID. On macOS this happens with multi-OpenVPN. Vortix won't elect an (external) tunnel as your Primary even if its routes would qualify — start the tunnel through vortix to get full tracking.",
    ),
    (
        "Reconnecting via …",
        "A connected tunnel dropped and vortix is automatically retrying. The 'via X' part names what its role was before the drop, so you know what to expect when it comes back.",
    ),
    (
        "n/a (awaiting input)",
        "The tunnel is waiting for you to type something (2FA code, passphrase). Press Enter while focused on Connection Details to surface the prompt overlay.",
    ),
];

    const ROLE_GLOSSARY_FOOTER: &str =
        "Full guide with examples + common confusions: docs/roles.md on GitHub.";

    // ────────────────────────────── Guard tab ───────────────────────────────

    /// Plain-English explainer for the Security Guard panel. Each entry is
    /// `(label, description_paragraph)` matching the same card-style
    /// layout as the Roles tab. Two clusters:
    ///   1. The three headline states (EXPOSED / PARTIAL / PROTECTED).
    ///   2. Each row the panel renders (IP, DNS, etc.) and
    ///      what makes that row light up vs stay quiet.
    const GUARD_GLOSSARY: &[(&str, &str)] = &[
    (
        "EXPOSED",
        "No tunnel is up, or no tunnel claims your kernel default route. All internet traffic flows via your normal ISP — websites see your real IPv4 (and IPv6 if you have it). If you intended a VPN, this is the alarm state: connect a profile or check why your tunnel dropped.",
    ),
    (
        "PARTIAL",
        "At least one tunnel is Connected, but none owns the default route (split-only topology), OR a primary IS up but a defense row is degraded (killswitch off, cipher weak, or DNS policy not verified). Declared subnets tunnel correctly; general internet traffic posture depends on which signal demoted the panel.",
    ),
    (
        "PROTECTED",
        "A tunnel owns your kernel default route, the cipher is modern AEAD, the kill switch is engaged, and the current DNS policy has been applied and read back. New outbound connections flow through the tunnel. This is the goal state for a full-tunnel VPN.",
    ),
    (
        "Identity → Real IPv4 / Real IPv6",
        "Your cached pre-VPN public addresses — what your ISP would expose you as if no tunnel were up. Always informational (no safety verdict on these rows): they're what you'd revert to if the VPN dropped. When your host has no IPv6 connectivity the row collapses to a single `Real IP` line; with v6 present, `Real IPv4` and `Real IPv6` render as separate rows. `Real IPv6` reads `checking…` until vortix can prove the v6 probe escaped any active tunnel (either a fully-disconnected sample or a tunnel whose AllowedIPs lack `::/0`).",
    ),
    (
        "Identity → Exit IPv4 / Exit IPv6",
        "The public addresses the rest of the internet sees you as right now. With a working full-tunnel VPN these are the tunnel's exit addresses and the rows read ✓. When `Exit IPv4` matches `Real IPv4` the row goes ✗ with 'real IPv4 exposed' — IPv4 masking has failed. The `Exit IPv6` row carries the same per-family verdict: ✓ when `public_ipv6` differs from `real_ipv6`, ✗ with 'v6 exposed — matches real IPv6' when they match.",
    ),
    (
        "Identity → Location",
        "Geo lookup of the IPv4 exit (city + country). Sanity check: connect a German VPN, this should say DE. If it still says your home country, the tunnel didn't take over the default route.",
    ),
    (
        "Identity → DNS",
        "The active primary VPN's intended system resolver, including DNS learned from an OpenVPN server. ✓ means Vortix read back that exact resolver policy and the kernel routes every resolver through the owning VPN interface. ⚠ means the VPN supplied no system resolver or either proof is unavailable. This covers system DNS, not application-owned encrypted DNS such as browser DoH. A recursive server's public egress address is not compared with the configured server because forwarding and anycast make that comparison unreliable.",
    ),
    (
        "Defense → Killswitch",
        "Current killswitch mode and runtime state. Modes: {off} (no firewall), {block_on_drop} (firewall armed but quiet while VPN is up; engages default-DROP egress the moment VPN drops — also reads 'VPN dropped' with 'press r to reconnect' sub-line during the drop window), {vpn_only} (firewall always engaged with per-tunnel ACCEPT rules — closes the gap-between-drop-and-reconnect leak window). Cycle modes with Shift+K.",
    ),
    (
        "Defense → Encryption",
        "The tunnel's cipher annotated with its security grade. ChaCha20-Poly1305 / AES-GCM → modern AEAD. AES-256-CBC / AES-256-CTR → strong. 3DES / AES-128-CBC → deprecated (alarm + 'upgrade to AES-GCM' sub-line). BF / DES / RC4 / NULL → INSECURE (loud alarm + 'broken cipher' sub-line).",
    ),
];

    const GUARD_GLOSSARY_FOOTER: &str =
        "Sigils tab covers the glyphs (✓ ✗ ⚠ ─); this tab covers what each row checks.";

    // ────────────────────────────── Rendering ──────────────────────────────

    const OVERLAY_MAX_WIDTH: u16 = 120;
    const TAB_STRIP_HEIGHT: u16 = 2;

    #[must_use]
    pub fn total_lines(tab: HelpTab) -> u16 {
        #[allow(clippy::cast_possible_truncation)]
        match tab {
            HelpTab::Keys => HELP_TEXT
                .iter()
                .enumerate()
                .map(|(section_idx, (_, bindings))| {
                    bindings.len() + 2 + usize::from(section_idx > 0)
                })
                .sum::<usize>() as u16,
            HelpTab::Roles => {
                // ~6 lines per entry (header + ~4 wrapped + blank) + leading blank + footer
                (1 + ROLE_GLOSSARY.len() * 6 + 2) as u16
            }
            HelpTab::Sigils => {
                // 1 header per category + ~2 lines per entry. Conservative upper bound.
                let entries = CATALOG.len();
                (2 + entries * 2 + 4) as u16
            }
            HelpTab::Guard => {
                // Same shape as Roles — ~6 lines per entry (header + wrapped
                // body + blank) + leading blank + footer.
                (1 + GUARD_GLOSSARY.len() * 6 + 2) as u16
            }
        }
    }

    pub fn render(frame: &mut Frame, scroll: u16, tab: HelpTab) {
        let area = frame.area();
        let width = area.width.saturating_sub(4).min(OVERLAY_MAX_WIDTH);
        let height = area
            .height
            .saturating_sub(2)
            .min(state::HELP_OVERLAY_MAX_HEIGHT);
        if width == 0 || height == 0 {
            return;
        }

        let overlay = Rect {
            x: (area.width / 2).saturating_sub(width / 2),
            y: (area.height / 2).saturating_sub(height / 2),
            width,
            height,
        };

        crate::ui::helpers::clear_area(frame, overlay);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().accent_primary))
            .title(Span::styled(
                " Help ",
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_bottom(Span::styled(
                " Tab next · Shift+Tab prev · ↑↓ j/k scroll · ? close ",
                Style::default().fg(theme::current().key_hint_desc),
            ));

        let inner = block.inner(overlay);
        frame.render_widget(block, overlay);

        // Top strip = tabs. Below = active tab content. Layout the inner
        // area into [tabs | divider | content].
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(TAB_STRIP_HEIGHT),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(inner);

        render_tab_strip(frame, chunks[0], tab);
        render_divider(frame, chunks[1]);

        let active_tab = HelpTab::ALL.iter().position(|t| *t == tab).unwrap_or(0);
        // Clamp scroll against the ACTUAL content-paragraph height
        // (chunks[2]), not the full inner area. The tab strip + divider
        // eat 3 rows from the top of inner; without accounting for that
        // here, max_scroll would underestimate and the bottom 3 lines of
        // each tab would be unreachable.
        let content_height = chunks[2].height;
        let max_scroll = total_lines(tab).saturating_sub(content_height);
        let clamped_scroll = scroll.min(max_scroll);

        let lines = match HelpTab::ALL[active_tab] {
            HelpTab::Keys => build_keys_lines(),
            HelpTab::Roles => build_glossary_lines(ROLE_GLOSSARY, Some(ROLE_GLOSSARY_FOOTER)),
            HelpTab::Sigils => build_sigils_lines(),
            HelpTab::Guard => build_guard_glossary_lines(),
        };
        let paragraph = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((clamped_scroll, 0));
        frame.render_widget(paragraph, chunks[2]);
    }

    /// Render the browser-style tab strip across the top of the overlay.
    /// Active tab gets accent + BOLD + UNDERLINED; inactive tabs get
    /// muted secondary text. ratatui's `Tabs` widget does the layout +
    /// separator handling consistently.
    fn render_tab_strip(frame: &mut Frame, area: Rect, active: HelpTab) {
        let titles: Vec<Line> = HelpTab::ALL
            .iter()
            .map(|t| Line::from(Span::styled(t.title(), Style::default())))
            .collect();
        let active_idx = HelpTab::ALL.iter().position(|t| *t == active).unwrap_or(0);
        let tabs = Tabs::new(titles)
            .select(active_idx)
            .style(Style::default().fg(theme::current().text_secondary))
            .highlight_style(
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )
            .divider(Span::styled(
                " │ ",
                Style::default().fg(theme::current().nord_polar_night_4),
            ));
        frame.render_widget(tabs, area);
    }

    fn render_divider(frame: &mut Frame, area: Rect) {
        let line = Line::from(Span::styled(
            "─".repeat(area.width as usize),
            Style::default().fg(theme::current().nord_polar_night_4),
        ));
        frame.render_widget(Paragraph::new(line), area);
    }

    fn build_keys_lines() -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::new();
        for (section_idx, (section, bindings)) in HELP_TEXT.iter().enumerate() {
            if section_idx > 0 {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("  {section}"),
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )));
            lines.push(Line::from(""));

            for (key, desc) in *bindings {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("    {key:<14}"),
                        Style::default()
                            .fg(theme::current().key_hint)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(*desc, Style::default().fg(theme::current().text_secondary)),
                ]));
            }
        }
        lines
    }

    /// Card-style glossary renderer for the Roles tab. Each entry:
    ///   blank
    ///   ●  <label>
    ///   <description, indented, wrapped naturally>
    fn build_glossary_lines(
        entries: &'static [(&'static str, &'static str)],
        footer: Option<&'static str>,
    ) -> Vec<Line<'static>> {
        build_glossary_lines_with(entries, footer, |_, description| description.to_string())
    }

    fn build_glossary_lines_with(
        entries: &'static [(&'static str, &'static str)],
        footer: Option<&'static str>,
        description_for: impl Fn(&str, &str) -> String,
    ) -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::with_capacity(entries.len() * 6 + 2);
        lines.push(Line::from(""));
        for (label, desc) in entries {
            lines.push(Line::from(vec![
                Span::styled(
                    "  \u{25cf}  ",
                    Style::default()
                        .fg(theme::current().accent_primary)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    *label,
                    Style::default()
                        .fg(theme::current().accent_primary)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(Span::styled(
                format!("     {}", description_for(label, desc)),
                Style::default().fg(theme::current().text_secondary),
            )));
            lines.push(Line::from(""));
        }
        if let Some(footer) = footer {
            lines.push(Line::from(Span::styled(
                format!("  {footer}"),
                Style::default()
                    .fg(theme::current().key_hint_desc)
                    .add_modifier(Modifier::ITALIC),
            )));
        }
        lines
    }

    fn build_guard_glossary_lines() -> Vec<Line<'static>> {
        build_glossary_lines_with(
            GUARD_GLOSSARY,
            Some(GUARD_GLOSSARY_FOOTER),
            |label, template| {
                if label != "Defense → Killswitch" {
                    return template.to_string();
                }
                template
                    .replace(
                        "{off}",
                        crate::control::killswitch::KillSwitchMode::Off.display_name(),
                    )
                    .replace(
                        "{block_on_drop}",
                        crate::control::killswitch::KillSwitchMode::Auto.display_name(),
                    )
                    .replace(
                        "{vpn_only}",
                        crate::control::killswitch::KillSwitchMode::AlwaysOn.display_name(),
                    )
            },
        )
    }

    /// 3-column grid for the Sigils tab. Each row:
    ///   <glyph in its real TUI color>  <label, bold>  <description, secondary>
    /// Grouped by [`SigilCategory`] with a category header above each group.
    fn build_sigils_lines() -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::with_capacity(CATALOG.len() * 2 + 6);

        for category in [SigilCategory::Sidebar, SigilCategory::SecurityGuard] {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  {}", category_title(category)),
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            )));
            lines.push(Line::from(""));

            for entry in CATALOG.iter().filter(|s| s.category == category) {
                lines.push(sigil_row(entry));
            }
        }
        lines
    }

    fn category_title(c: SigilCategory) -> &'static str {
        match c {
            SigilCategory::Sidebar => "Sidebar (per-tunnel badges + suffixes)",
            SigilCategory::SecurityGuard => "Security Guard (per-row sigils)",
        }
    }

    /// One row of the Sigils tab. The glyph is rendered in its actual
    /// TUI color (the one the renderer applies), so the help-overlay
    /// swatch matches what users see on screen byte-for-byte.
    fn sigil_row(entry: &'static Sigil) -> Line<'static> {
        // Column widths chosen to fit comfortably at the 95-col overlay:
        //   glyph column: 4 cells (1 glyph + 3 padding for visual gutter)
        //   label column: 24 cells
        //   description: rest, wraps naturally
        Line::from(vec![
            Span::styled(format!("    {}   ", entry.glyph), entry.style()),
            Span::styled(
                format!("{:<22}", entry.label),
                Style::default()
                    .fg(theme::current().text_primary)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                entry.description,
                Style::default().fg(theme::current().text_secondary),
            ),
        ])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn multi_tunnel_keys_are_documented() {
            // Smoke check that the multi-tunnel keys (Shift+D, B on
            // takeover, etc.) all surfaced in the keybindings section.
            use std::fmt::Write;
            let blob = HELP_TEXT
                .iter()
                .flat_map(|(_, bindings)| bindings.iter())
                .fold(String::new(), |mut acc, (k, d)| {
                    let _ = writeln!(acc, "{k} {d}");
                    acc
                });
            assert!(blob.contains("Disconnect ALL"));
            assert!(blob.contains("Connect both"));
        }

        #[test]
        fn palette_key_is_documented() {
            let global = HELP_TEXT
                .iter()
                .find(|(section, _)| *section == "Global")
                .map(|(_, bindings)| *bindings)
                .expect("Global help section must exist");
            assert!(global.contains(&("p", "Switch color theme")));
        }

        #[test]
        fn role_glossary_covers_every_label_role_line_can_emit() {
            let labels: Vec<&str> = ROLE_GLOSSARY.iter().map(|(k, _)| *k).collect();
            for expected in [
                "Primary",
                "Split tunnel",
                "Split tunnel (yielded)",
                "Split tunnel (multi, yielded)",
                "(external) suffix",
                "Reconnecting via …",
            ] {
                assert!(
                    labels.contains(&expected),
                    "Roles tab must document `{expected}`; found: {labels:?}"
                );
            }
        }

        #[test]
        fn sigils_tab_renders_every_catalog_entry() {
            // The Sigils tab content is generated from CATALOG — make sure
            // EVERY entry produces a row. This is the drift-detection
            // backstop: adding a sigil to the catalog automatically makes
            // it appear in help; removing one from the catalog removes it.
            let lines = build_sigils_lines();
            let blob: String = lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .map(|s| s.content.as_ref())
                .collect::<String>();
            for entry in CATALOG {
                assert!(
                    blob.contains(entry.label),
                    "Sigils tab missing label `{}`; CATALOG entry not surfaced",
                    entry.label
                );
            }
        }

        #[test]
        fn keys_total_lines_invariant_holds() {
            let expected = u16::try_from(build_keys_lines().len()).expect("fits in u16");
            assert_eq!(total_lines(HelpTab::Keys), expected);
        }

        #[test]
        fn help_tab_cycle_wraps_in_both_directions() {
            let cycle: Vec<HelpTab> =
                std::iter::successors(Some(HelpTab::Keys), |t| Some(t.next()))
                    .take(HelpTab::ALL.len() + 1)
                    .collect();
            assert_eq!(
                cycle,
                vec![
                    HelpTab::Keys,
                    HelpTab::Roles,
                    HelpTab::Sigils,
                    HelpTab::Guard,
                    HelpTab::Keys
                ]
            );
            assert_eq!(HelpTab::Keys.prev(), HelpTab::Guard);
        }

        #[test]
        fn guard_glossary_covers_headline_states_and_every_panel_row() {
            // Drift-detection backstop: the Guard tab must document each
            // headline state the panel can render AND every row the panel
            // shows. If a new row or state is added to security.rs, the
            // assertion fails until the glossary catches up. Labels MUST
            // match the panel's actual row labels byte-for-byte.
            let labels: Vec<&str> = GUARD_GLOSSARY.iter().map(|(k, _)| *k).collect();
            for expected in [
                // Headline states (Verdict enum in security.rs).
                "EXPOSED",
                "PARTIAL",
                "PROTECTED",
                // Identity rows.
                "Identity → Real IPv4 / Real IPv6",
                "Identity → Exit IPv4 / Exit IPv6",
                "Identity → Location",
                "Identity → DNS",
                // Defense rows.
                "Defense → Killswitch",
                "Defense → Encryption",
            ] {
                assert!(
                    labels.contains(&expected),
                    "Guard tab must document `{expected}`; found: {labels:?}"
                );
            }
        }

        #[test]
        fn guard_glossary_uses_the_canonical_long_form_killswitch_label() {
            let rendered = build_guard_glossary_lines()
                .into_iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            for mode in [
                crate::control::killswitch::KillSwitchMode::Off,
                crate::control::killswitch::KillSwitchMode::Auto,
                crate::control::killswitch::KillSwitchMode::AlwaysOn,
            ] {
                assert!(rendered.contains(mode.display_name()));
            }
            assert!(!rendered.contains("{block_on_drop}"));
        }
    }
}
pub mod import {
    use crate::{constants, ui::theme};
    use ratatui::{
        layout::Alignment,
        style::Style,
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
        Frame,
    };
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

    fn display_character(character: char) -> char {
        if character.is_control() {
            '\u{fffd}'
        } else {
            character
        }
    }

    fn suffix_window(characters: &[char], budget: usize) -> String {
        let mut width = 0;
        let mut start = characters.len();
        for (index, character) in characters.iter().enumerate().rev() {
            let character_width = display_character(*character).width().unwrap_or(1);
            let ellipsis = usize::from(index > 0);
            if width + character_width + ellipsis > budget {
                break;
            }
            width += character_width;
            start = index;
        }
        let mut output = String::new();
        if start > 0 && budget > 0 {
            output.push('…');
        }
        output.extend(characters[start..].iter().copied().map(display_character));
        output
    }

    fn prefix_window(characters: &[char], budget: usize) -> String {
        let mut width = 0;
        let mut end = 0;
        for (index, character) in characters.iter().enumerate() {
            let character_width = display_character(*character).width().unwrap_or(1);
            let ellipsis = usize::from(index + 1 < characters.len());
            if width + character_width + ellipsis > budget {
                break;
            }
            width += character_width;
            end = index + 1;
        }
        let mut output = characters[..end]
            .iter()
            .copied()
            .map(display_character)
            .collect::<String>();
        if end < characters.len() && budget > 0 {
            output.push('…');
        }
        output
    }

    /// Window a long path around its insertion cursor so the cursor is always
    /// visible without widening the compact import dialog.
    fn visible_path(path: &str, cursor: usize, max_width: usize) -> (String, String, String) {
        let characters = path.chars().collect::<Vec<_>>();
        let cursor = cursor.min(characters.len());
        let cursor_character = characters
            .get(cursor)
            .copied()
            .map_or('█', display_character);
        let cursor_text = cursor_character.to_string();
        let remaining = max_width.saturating_sub(cursor_text.width());
        let (left_budget, right_budget) = if cursor == characters.len() {
            (remaining, 0)
        } else if cursor == 0 {
            (0, remaining)
        } else {
            (remaining.div_ceil(2), remaining / 2)
        };
        let after_start = cursor + usize::from(cursor < characters.len());
        (
            suffix_window(&characters[..cursor], left_budget),
            cursor_text,
            prefix_window(&characters[after_start..], right_budget),
        )
    }

    pub fn render(frame: &mut Frame, path: &str, cursor: usize) {
        let area = frame.area();
        let popup_area = crate::ui::helpers::centered_rect_fixed(
            58.min(area.width.saturating_sub(2)),
            12.min(area.height.saturating_sub(2)),
            area,
        );

        crate::ui::helpers::clear_area(frame, popup_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().accent_primary))
            .title(constants::TITLE_IMPORT_PROFILE)
            .title_bottom(Line::from(constants::TITLE_IMPORT_FOOTER).centered());

        let inner = block.inner(popup_area);
        frame.render_widget(block, popup_area);

        let (before, cursor_char, after) =
            visible_path(path, cursor, usize::from(inner.width.saturating_sub(3)));

        let text = vec![
            Line::from(Span::styled(
                constants::PROMPT_IMPORT_PATH,
                Style::default().fg(theme::current().text_primary),
            )),
            Line::from(""),
            Line::from(
                std::iter::once(Span::styled(
                    " > ",
                    Style::default().fg(theme::current().text_secondary),
                ))
                .chain(crate::ui::helpers::text_entry_spans(
                    before,
                    cursor_char,
                    after,
                ))
                .collect::<Vec<_>>(),
            ),
            Line::from(""),
            Line::from(Span::styled(
                "Directory paths import every supported profile.",
                Style::default().fg(theme::current().accent_secondary),
            )),
            Line::from(Span::styled(
                constants::LABEL_SUPPORTED_FORMATS,
                Style::default().fg(theme::current().text_secondary),
            )),
            Line::from(vec![
                Span::styled(
                    format!("  {}", constants::EXT_CONF),
                    Style::default().fg(theme::current().nord_purple),
                ),
                Span::styled(
                    format!(" → {}", constants::PROTO_WIREGUARD),
                    Style::default().fg(theme::current().text_secondary),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    format!("  {}", constants::EXT_OVPN),
                    Style::default().fg(theme::current().warning),
                ),
                Span::styled(
                    format!(" → {}", constants::PROTO_OPENVPN),
                    Style::default().fg(theme::current().text_secondary),
                ),
            ]),
        ];

        frame.render_widget(Paragraph::new(text).alignment(Alignment::Left), inner);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ratatui::{backend::TestBackend, Terminal};

        #[test]
        fn supported_formats_remain_visible_at_minimum_terminal_size() {
            let mut terminal = Terminal::new(TestBackend::new(60, 20)).unwrap();
            terminal
                .draw(|frame| render(frame, "/tmp/profiles", 13))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let output = buffer
                .content
                .iter()
                .map(ratatui::buffer::Cell::symbol)
                .collect::<String>();
            assert!(output.contains(".conf"), "{output}");
            assert!(output.contains("WireGuard"), "{output}");
            assert!(output.contains(".ovpn"), "{output}");
            assert!(output.contains("OpenVPN"), "{output}");
        }

        #[test]
        fn long_path_keeps_the_cursor_visible_inside_the_fixed_dialog() {
            let path = "/Users/harshit/Library/Application Support/vortix/profiles/imports";
            let (before, cursor, after) = visible_path(path, path.chars().count(), 20);
            assert!(before.starts_with('…'), "{before}");
            assert_eq!(cursor, "█");
            assert!(after.is_empty());
            assert!(before.width() + cursor.width() <= 20);
        }

        #[test]
        fn path_window_sanitizes_control_characters_without_changing_cursor_position() {
            let (before, cursor, after) = visible_path("ab\u{1b}cd", 2, 20);
            assert_eq!(before, "ab");
            assert_eq!(cursor, "�");
            assert_eq!(after, "cd");
        }
    }
}
pub mod rename {
    use crate::ui::theme;
    use ratatui::{
        layout::Rect,
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
        Frame,
    };

    pub fn render(frame: &mut Frame, name: &str, cursor: usize) {
        let area = frame.area();
        let width = 45u16.min(area.width.saturating_sub(4));
        let height = 5u16;
        let overlay = Rect {
            x: (area.width / 2).saturating_sub(width / 2),
            y: (area.height / 2).saturating_sub(height / 2),
            width,
            height,
        };

        crate::ui::helpers::clear_area(frame, overlay);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().accent_primary))
            .title(Span::styled(
                " Rename Profile ",
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_bottom(Span::styled(
                " Enter confirm │ Esc cancel ",
                Style::default().fg(theme::current().key_hint_desc),
            ));

        let inner = block.inner(overlay);
        frame.render_widget(block, overlay);

        let before: String = name.chars().take(cursor).collect();
        let cursor_char: String = name
            .chars()
            .nth(cursor)
            .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string());
        let after: String = name.chars().skip(cursor + 1).collect();

        let mut spans = vec![Span::styled(
            "> ",
            Style::default().fg(theme::current().accent_primary),
        )];
        spans.extend(crate::ui::helpers::text_entry_spans(
            before,
            cursor_char,
            after,
        ));

        frame.render_widget(
            Paragraph::new(Line::from(spans)).alignment(ratatui::layout::Alignment::Left),
            inner,
        );
    }
}
pub mod search {
    use crate::app::App;
    use crate::ui::theme;
    use ratatui::{
        layout::Rect,
        style::{Modifier, Style},
        text::{Line, Span},
        widgets::{Block, Borders, Paragraph},
        Frame,
    };

    pub fn render(frame: &mut Frame, app: &App, query: &str, cursor: usize, total: usize) {
        let area = frame.area();
        let bar_area = Rect {
            x: 1,
            y: area.height.saturating_sub(3),
            width: area.width.saturating_sub(2).min(60),
            height: 3,
        };

        crate::ui::helpers::clear_area(frame, bar_area);

        let match_count = app.search_match_count;

        let count_text = if query.is_empty() {
            format!("{total} profiles")
        } else if match_count == 0 {
            "no matches".to_string()
        } else {
            format!("{match_count} of {total}")
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme::current().accent_primary))
            .title(Span::styled(
                " Search ",
                Style::default()
                    .fg(theme::current().accent_primary)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_bottom(Line::from(Span::styled(
                format!(" {count_text} "),
                Style::default().fg(theme::current().key_hint_desc),
            )));

        let inner = block.inner(bar_area);
        frame.render_widget(block, bar_area);

        let before: String = query.chars().take(cursor).collect();
        let cursor_char: String = query
            .chars()
            .nth(cursor)
            .map_or_else(|| "\u{2588}".to_string(), |c| c.to_string());
        let after: String = query.chars().skip(cursor + 1).collect();

        let mut spans = vec![Span::styled(
            "/",
            Style::default().fg(theme::current().accent_primary),
        )];
        spans.extend(crate::ui::helpers::text_entry_spans(
            before,
            cursor_char,
            after,
        ));

        if query.is_empty() {
            spans.push(Span::styled(
                "type to filter...",
                Style::default().fg(theme::current().inactive),
            ));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), inner);
    }
}
pub mod toast {
    //! Toast notification overlay

    use crate::app::App;
    use ratatui::{
        layout::{Alignment, Constraint, Layout, Rect},
        style::{Modifier, Style},
        text::Span,
        widgets::{Block, Borders, Paragraph},
        Frame,
    };
    use unicode_width::UnicodeWidthStr;

    fn toast_geometry(area: Rect, message: &str) -> Option<(Rect, u16)> {
        if area.width < 6 || area.height < 5 {
            return None;
        }
        let width = (area.width / 3)
            .clamp(28, 50)
            .min(area.width.saturating_sub(2));
        let inner_width = usize::from(width.saturating_sub(4)).max(1);
        let estimated_lines = message.lines().fold(0usize, |total, line| {
            total.saturating_add(line.width().max(1).div_ceil(inner_width))
        });
        let estimated_lines = u16::try_from(estimated_lines).unwrap_or(u16::MAX).max(1);
        let height = estimated_lines
            .saturating_add(4)
            .max(5)
            .min(area.height.saturating_sub(2));
        let text_lines = estimated_lines.min(height.saturating_sub(2));
        Some((
            Rect {
                x: area.width.saturating_sub(width + 1),
                y: 1,
                width,
                height,
            },
            text_lines,
        ))
    }

    /// Render toast notification (anchored to top-right corner)
    pub fn render(frame: &mut Frame, app: &App) {
        if let Some(ref toast) = app.toast {
            let area = frame.area();
            let Some((toast_area, text_lines)) = toast_geometry(area, &toast.message) else {
                return;
            };

            crate::ui::helpers::clear_area(frame, toast_area);

            let t = crate::ui::theme::current();
            let (title, bg_color, border_color) = match toast.toast_type {
                crate::app::state::ToastType::Info => (" INFO ", t.toast_info, t.toast_info),
                crate::app::state::ToastType::Success => {
                    (" SUCCESS ", t.toast_success, t.toast_success)
                }
                crate::app::state::ToastType::Warning => {
                    (" WARNING ", t.toast_warning, t.toast_warning)
                }
                crate::app::state::ToastType::Error => (" ERROR ", t.toast_error, t.toast_error),
            };

            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(t.text_dark)
                        .bg(bg_color)
                        .add_modifier(Modifier::BOLD),
                ))
                .title_bottom(Span::styled(
                    " Esc dismiss ",
                    Style::default().fg(t.key_hint_desc),
                ));

            let inner_area = block.inner(toast_area);
            frame.render_widget(block, toast_area);

            let vertical_chunks = Layout::vertical([
                Constraint::Fill(1),
                Constraint::Length(text_lines),
                Constraint::Fill(1),
            ])
            .split(inner_area);

            let paragraph = Paragraph::new(toast.message.clone())
                .wrap(ratatui::widgets::Wrap { trim: true })
                .alignment(Alignment::Center);

            frame.render_widget(paragraph, vertical_chunks[1]);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn long_toast_never_exceeds_the_terminal() {
            let area = Rect::new(0, 0, 80, 12);
            let (toast, text_lines) = toast_geometry(area, &"DNS failure ".repeat(80)).unwrap();
            assert!(toast.right() <= area.right());
            assert!(toast.bottom() <= area.bottom());
            assert!(text_lines <= toast.height.saturating_sub(2));
        }

        #[test]
        fn tiny_terminal_suppresses_an_unreadable_toast() {
            assert!(toast_geometry(Rect::new(0, 0, 5, 4), "error").is_none());
        }
    }
}
