//! Config file viewer overlay

use crate::app::App;
use crate::theme;
use crate::ui::helpers::centered_rect;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState},
    Frame,
};
use std::path::PathBuf;

/// Render config file viewer overlay
pub fn render(frame: &mut Frame, app: &App) {
    let area = centered_rect(85, 85, frame.area());

    // Clear the background
    frame.render_widget(Clear, area);

    let (config_content, profile_name, config_path): (&str, String, PathBuf) =
        if let Some(idx) = app.profile_list_state.selected() {
            if let Some(profile) = app.profiles.get(idx) {
                let content = app
                    .cached_config_content
                    .as_deref()
                    .unwrap_or("No config loaded");
                (content, profile.name.clone(), profile.config_path.clone())
            } else {
                ("No profile selected", String::new(), PathBuf::new())
            }
        } else {
            ("No profile selected", String::new(), PathBuf::new())
        };

    let title = if profile_name.is_empty() {
        " Config Viewer ".to_string()
    } else {
        let max_name = (area.width as usize).saturating_sub(14); // " " + " - Config " + borders
        let short = crate::utils::truncate(&profile_name, max_name);
        format!(" {short} - Config ")
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::BORDER_FOCUSED))
        .title(title)
        .title_bottom(Line::from(" [Esc] Close  [↑/↓] Scroll ").centered());

    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Show the file path at the top
    let path_style = Style::default().fg(Color::DarkGray);

    // Parse config and apply syntax highlighting
    let lines: Vec<Line> = config_content.lines().map(highlight_config_line).collect();

    // Create paragraph with scrolling
    let total_lines = lines.len();
    let paragraph = Paragraph::new(lines)
        .style(Style::default().fg(theme::TEXT_PRIMARY))
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
            Span::styled(path_display, Style::default().fg(theme::TEXT_SECONDARY)),
            Span::styled(scroll_info, Style::default().fg(Color::DarkGray)),
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
        .style(Style::default().fg(theme::NORD_POLAR_NIGHT_4))
        .thumb_style(Style::default().fg(theme::ACCENT_PRIMARY));

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

/// Apply syntax highlighting to config lines
fn highlight_config_line(line: &str) -> Line<'static> {
    let line = line.to_string();
    let trimmed = line.trim();

    // Comments
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return Line::from(Span::styled(line, Style::default().fg(Color::DarkGray)));
    }

    // Section headers [Interface], [Peer], etc.
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return Line::from(Span::styled(
            line,
            Style::default()
                .fg(theme::NORD_YELLOW)
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
            Span::styled(key.to_string(), Style::default().fg(theme::NORD_FROST_2)),
            Span::styled("=", Style::default().fg(Color::DarkGray)),
            Span::styled(masked_value, Style::default().fg(theme::TEXT_PRIMARY)),
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
                        Style::default().fg(theme::NORD_FROST_2),
                    ),
                    Span::styled(" ", Style::default()),
                    Span::styled(
                        parts[1].to_string(),
                        Style::default().fg(theme::TEXT_PRIMARY),
                    ),
                ]);
            }
            return Line::from(Span::styled(line, Style::default().fg(theme::NORD_FROST_2)));
        }
    }

    // Default: just return the line
    Line::from(Span::styled(line, Style::default().fg(theme::TEXT_PRIMARY)))
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
