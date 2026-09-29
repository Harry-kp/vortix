use std::borrow::Cow;

use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear},
    Frame,
};
use unicode_width::UnicodeWidthChar;

use crate::ui::theme;

/// The dim vertical rule between panel segments.
pub(crate) fn divider() -> Span<'static> {
    Span::styled(
        " │",
        Style::default().fg(theme::current().nord_polar_night_4),
    )
}

/// `divider`, padded on the right for segments that don't lead with a space.
pub(crate) fn divider_padded() -> Span<'static> {
    Span::styled(
        " │ ",
        Style::default().fg(theme::current().nord_polar_night_4),
    )
}

/// A `label: value` detail row — label in secondary, value in `color`.
pub(crate) fn detail_row<'a>(
    label: &'a str,
    value: impl Into<Cow<'a, str>>,
    color: Color,
) -> Line<'a> {
    Line::from(vec![
        Span::styled(label, Style::default().fg(theme::current().text_secondary)),
        Span::styled(value, Style::default().fg(color)),
    ])
}

/// `text` word-wrapped to `width` columns, each line indented by `indent` spaces.
pub(crate) fn wrapped_lines(
    text: &str,
    width: usize,
    indent: usize,
    style: Style,
) -> Vec<Line<'static>> {
    wrap_to_width(text, width.saturating_sub(indent))
        .into_iter()
        .map(|line| {
            Line::from(vec![
                Span::raw(" ".repeat(indent)),
                Span::styled(line, style),
            ])
        })
        .collect()
}

/// `line` cut to `width` columns: the span that crosses the edge ends in an ellipsis and the
/// spans after it go, so a row never stops mid-word at a panel edge.
pub(crate) fn fit_line(line: Line<'_>, width: usize) -> Line<'_> {
    if line.width() <= width {
        return line;
    }
    let Line {
        spans,
        style,
        alignment,
    } = line;
    let mut used = 0;
    let mut kept = Vec::new();
    for mut span in spans {
        let span_width = span.width();
        if used + span_width < width {
            used += span_width;
            kept.push(span);
            continue;
        }
        // The trailing space makes a span that ends exactly at the edge still get its ellipsis.
        span.content = truncate_to_width(&format!("{} ", span.content), width - used).into();
        kept.push(span);
        break;
    }
    Line {
        spans: kept,
        style,
        alignment,
    }
}

/// `value`, or `fallback` when the backend reported the field blank.
pub(crate) fn nonempty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

/// Green under 50ms, yellow under 150ms, red beyond.
pub(crate) fn latency_color(latency_ms: u64) -> Color {
    if latency_ms < 50 {
        theme::current().success
    } else if latency_ms < 150 {
        theme::current().yellow
    } else {
        theme::current().error
    }
}

/// Clear an area and repaint the active theme's owned surface.
pub(crate) fn clear_area(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(
            Style::default()
                .fg(crate::ui::theme::current().text_primary)
                .bg(crate::ui::theme::current().panel_bg),
        ),
        area,
    );
}

/// Center a rectangle sized as a percentage of the parent area.
pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Percentage(percent_y)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Percentage(percent_x)]).flex(Flex::Center);

    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// Center a rectangle with fixed pixel dimensions.
pub(crate) fn centered_rect_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([Constraint::Length(height)]).flex(Flex::Center);
    let horizontal = Layout::horizontal([Constraint::Length(width)]).flex(Flex::Center);

    let [area] = vertical.areas(area);
    let [area] = horizontal.areas(area);
    area
}

/// `character`, or `�` for a control character that would corrupt the terminal.
pub(crate) fn display_character(character: char) -> char {
    if character.is_control() {
        '\u{FFFD}'
    } else {
        character
    }
}

/// Truncate text to a terminal-column budget, including the ellipsis.
pub(crate) fn truncate_to_width(text: &str, max_width: usize) -> String {
    let sanitized: String = text.chars().map(display_character).collect();
    let sanitized_width = sanitized
        .chars()
        .map(|character| character.width().unwrap_or(1))
        .sum::<usize>();

    if sanitized_width <= max_width {
        return sanitized;
    }
    if max_width == 0 {
        return String::new();
    }
    // A cell too narrow for "..." keeps a prefix: "wg…" says more than "...".
    let (content_width, ellipsis) = if max_width <= 3 {
        (max_width - 1, "…")
    } else {
        (max_width - 3, "...")
    };
    let mut width = 0;
    let mut truncated = String::new();
    for character in sanitized.chars() {
        let character_width = character.width().unwrap_or(1);
        if width + character_width > content_width {
            break;
        }
        truncated.push(character);
        width += character_width;
    }
    truncated.push_str(ellipsis);
    truncated
}

/// Keep the end of `text` within `budget` columns, marking a cut start with `…`.
pub(crate) fn truncate_start_to_width(text: &str, budget: usize) -> String {
    let characters: Vec<char> = text.chars().map(display_character).collect();
    let mut width = 0;
    let mut start = characters.len();
    for (index, character) in characters.iter().enumerate().rev() {
        let character_width = character.width().unwrap_or(1);
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
    output.extend(&characters[start..]);
    output
}

/// Word-wrap `text` into lines of at most `width` columns; a word longer
/// than a line is split.
pub(crate) fn wrap_to_width(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0;
    for word in text.split_whitespace() {
        let word_width: usize = word.chars().map(|c| c.width().unwrap_or(1)).sum();
        if line_width > 0 && line_width + 1 + word_width > width {
            lines.push(std::mem::take(&mut line));
            line_width = 0;
        } else if line_width > 0 {
            line.push(' ');
            line_width += 1;
        }
        for character in word.chars() {
            let character_width = character.width().unwrap_or(1);
            if line_width > 0 && line_width + character_width > width {
                lines.push(std::mem::take(&mut line));
                line_width = 0;
            }
            line.push(character);
            line_width += character_width;
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Typed text, a blinking cursor, then the remainder.
///
/// Every text-entry overlay draws this. Keeping the cursor's treatment here
/// stops one field blinking differently from the next.
pub(crate) fn text_entry_spans(
    before: String,
    cursor: String,
    after: String,
) -> Vec<Span<'static>> {
    let theme = crate::ui::theme::current();
    let mut spans = vec![
        Span::styled(before, Style::default().fg(theme.text_primary)),
        Span::styled(
            cursor,
            Style::default()
                .fg(theme.accent_secondary)
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::SLOW_BLINK),
        ),
    ];
    if !after.is_empty() {
        spans.push(Span::styled(after, Style::default().fg(theme.text_primary)));
    }
    spans
}

/// Formats bytes per second into a human-readable string.
///
/// # Arguments
///
/// * `bytes` - Number of bytes per second
///
/// # Returns
///
/// A formatted string with appropriate units (B/s, KB/s, or MB/s).
///
/// # Example
///
/// ```ignore
/// assert_eq!(format_bytes_speed(1_500_000), "1.5 MB/s");
/// assert_eq!(format_bytes_speed(1_500), "1.5 KB/s");
/// ```
#[must_use]
pub fn format_bytes_speed(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB/s", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB/s", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB/s", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B/s")
    }
}

/// Returns the current local time formatted as HH:MM:SS.
///
/// Uses libc `localtime_r` for zero-overhead local time formatting
/// (called every tick, so avoiding a subprocess matters).
#[must_use]
pub fn format_local_time() -> String {
    format_system_time_local(std::time::SystemTime::now())
}

/// Converts any `SystemTime` into a local `HH:MM:SS` string.
///
/// Used for both "right now" timestamps (via `format_local_time()`) and for
/// formatting historical log entries in the TUI.
#[must_use]
pub fn format_system_time_local(time: std::time::SystemTime) -> String {
    format_system_time_inner(time).unwrap_or_else(|| "00:00:00".to_string())
}

#[allow(unsafe_code)]
fn format_system_time_inner(time: std::time::SystemTime) -> Option<String> {
    let secs = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    // SAFETY: localtime_r writes into our stack-allocated `tm` and is
    // thread-safe (unlike localtime). We pass a valid pointer to both args.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // The type comes from localtime_r, so the (deprecated on musl) libc::time_t alias is never named.
    let time_t = secs.try_into().ok()?;
    let result =
        unsafe { libc::localtime_r(std::ptr::from_ref(&time_t), std::ptr::from_mut(&mut tm)) };
    if result.is_null() {
        return None;
    }

    Some(format!(
        "{:02}:{:02}:{:02}",
        tm.tm_hour, tm.tm_min, tm.tm_sec
    ))
}

/// Formats a `SystemTime` into a compact relative time string (e.g., 1s, 2m, 3h, 4d).
#[must_use]
pub fn format_relative_time(time: std::time::SystemTime) -> String {
    let now = std::time::SystemTime::now();
    match now.duration_since(time) {
        Ok(duration) => {
            let secs = duration.as_secs();
            if secs < 60 {
                format!("{secs}s")
            } else if secs < 3600 {
                format!("{}m", secs / 60)
            } else if secs < 86400 {
                format!("{}h", secs / 3600)
            } else if secs < 2_592_000 {
                // 30 days
                format!("{}d ago", secs / 86400)
            } else if secs < 31_536_000 {
                // 365 days
                format!("{}M ago", secs / 2_592_000)
            } else {
                format!("{}Y ago", secs / 31_536_000)
            }
        }
        Err(_) => "now".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    use std::time::{Duration, SystemTime};
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn centered_rect_fixed_centers_within_area() {
        let area = Rect::new(0, 0, 100, 50);
        let r = centered_rect_fixed(20, 10, area);
        assert_eq!(r.width, 20);
        assert_eq!(r.height, 10);
        assert_eq!(r.x, 40); // (100 - 20) / 2
        assert_eq!(r.y, 20); // (50 - 10) / 2
    }

    #[test]
    fn centered_rect_fixed_clamps_to_area() {
        let area = Rect::new(0, 0, 10, 10);
        let r = centered_rect_fixed(30, 30, area);
        assert!(r.width <= area.width);
        assert!(r.height <= area.height);
    }

    #[test]
    fn centered_rect_percentage_scales() {
        let area = Rect::new(0, 0, 100, 100);
        let r = centered_rect(50, 50, area);
        assert_eq!(r.width, 50);
        assert_eq!(r.height, 50);
    }

    #[test]
    fn fit_line_cuts_the_span_at_the_edge_and_drops_the_rest() {
        let line = Line::from(vec![
            Span::raw("Stats   : "),
            Span::raw("PID 12345 | Drops "),
            Span::raw("0"),
        ]);
        let fitted = fit_line(line, 22);
        assert_eq!(fitted.width(), 22);
        assert_eq!(fitted.to_string(), "Stats   : PID 12345...");
        let exact = fit_line(Line::from(vec![Span::raw("abcd"), Span::raw("ef")]), 4);
        assert_eq!(exact.to_string(), "a...");
    }

    #[test]
    fn truncate_start_keeps_the_end() {
        assert_eq!(truncate_start_to_width("/a/b/wg.conf", 9), "…/wg.conf");
        assert_eq!(truncate_start_to_width("wg.conf", 8), "wg.conf");
    }

    #[test]
    fn wraps_on_words_and_splits_only_overlong_ones() {
        assert_eq!(
            wrap_to_width("Connect to a profile to protect", 12),
            ["Connect to a", "profile to", "protect"]
        );
        assert_eq!(wrap_to_width("abcdefgh ij", 4), ["abcd", "efgh", "ij"]);
    }

    #[test]
    fn truncates_wide_text_to_terminal_column_budget() {
        let truncated = truncate_to_width("office-世界-network", 12);
        assert!(truncated.width() <= 12);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn a_narrow_cell_keeps_a_prefix_of_the_name() {
        assert_eq!(truncate_to_width("wg08", 3), "wg…");
        assert_eq!(truncate_to_width("wg08", 1), "…");
        assert_eq!(truncate_to_width("wg08", 0), "");
    }

    #[test]
    fn truncation_sanitizes_terminal_controls_even_when_text_fits() {
        assert_eq!(
            truncate_to_width("profile\u{1b}[31m\n", 32),
            "profile�[31m�"
        );
    }

    #[test]
    fn sanitized_controls_consume_terminal_width_when_truncated() {
        let truncated = truncate_to_width("\u{1b}abcdef", 5);
        assert_eq!(truncated, "�a...");
        assert_eq!(truncated.width(), 5);
    }

    #[test]
    fn clear_area_paints_each_fixed_palette_and_leaves_terminal_adaptive() {
        for choice in [
            crate::ui::theme::ThemeChoice::Synthwave,
            crate::ui::theme::ThemeChoice::Terminal,
            crate::ui::theme::ThemeChoice::CatppuccinMocha,
            crate::ui::theme::ThemeChoice::Dracula,
            crate::ui::theme::ThemeChoice::Nord,
            crate::ui::theme::ThemeChoice::GruvboxDark,
            crate::ui::theme::ThemeChoice::TokyoNight,
        ] {
            let mut terminal = Terminal::new(TestBackend::new(2, 1)).unwrap();
            crate::ui::theme::with_choice(choice, || {
                terminal
                    .draw(|frame| clear_area(frame, frame.area()))
                    .unwrap();
            });
            let cell = &terminal.backend().buffer()[(0, 0)];
            assert_eq!(cell.bg, choice.palette().panel_bg, "{choice:?}");
            assert_eq!(cell.fg, choice.palette().text_primary, "{choice:?}");
        }
    }

    #[test]
    fn test_format_bytes_speed_bytes() {
        assert_eq!(format_bytes_speed(0), "0 B/s");
        assert_eq!(format_bytes_speed(2_500_000_000), "2.5 GB/s");
        assert_eq!(format_bytes_speed(500), "500 B/s");
        assert_eq!(format_bytes_speed(999), "999 B/s");
    }

    #[test]
    fn test_format_bytes_speed_kilobytes() {
        assert_eq!(format_bytes_speed(1_000), "1.0 KB/s");
        assert_eq!(format_bytes_speed(1_500), "1.5 KB/s");
        assert_eq!(format_bytes_speed(999_999), "1000.0 KB/s");
    }

    #[test]
    fn test_format_bytes_speed_megabytes() {
        assert_eq!(format_bytes_speed(1_000_000), "1.0 MB/s");
        assert_eq!(format_bytes_speed(1_500_000), "1.5 MB/s");
        assert_eq!(format_bytes_speed(100_000_000), "100.0 MB/s");
    }

    #[test]
    fn test_format_relative_time() {
        let now = SystemTime::now();

        // Seconds
        let just_now = now - Duration::from_secs(5);
        assert_eq!(format_relative_time(just_now), "5s");

        // Minutes
        let five_mins = now - Duration::from_secs(300);
        assert_eq!(format_relative_time(five_mins), "5m");

        // Hours
        let two_hours = now - Duration::from_secs(7200);
        assert_eq!(format_relative_time(two_hours), "2h");

        // Days
        let three_days = now - Duration::from_secs(86400 * 3);
        assert_eq!(format_relative_time(three_days), "3d ago");

        // Months
        let two_months = now - Duration::from_secs(2_592_000 * 2);
        assert_eq!(format_relative_time(two_months), "2M ago");

        // Years
        let three_years = now - Duration::from_secs(31_536_000 * 3);
        assert_eq!(format_relative_time(three_years), "3Y ago");

        // Future or now
        let future = now + Duration::from_secs(10);
        assert_eq!(format_relative_time(future), "now");
    }
}
