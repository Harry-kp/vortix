//! UI rendering module

mod dashboard;
mod footer;
pub mod helpers;
/// Overlays are reachable from the App layer because the open-config
/// path pre-builds the cached `Vec<Line>` once (`CachedConfigView`)
/// instead of letting the renderer re-parse on every frame.
pub(crate) mod overlays;
/// Single source of truth for every sigil rendered in the TUI.
/// Renderers + the `?` help overlay both read from `sigils::CATALOG`.
pub(crate) mod sigils;
pub mod theme;

use crate::app::{App, Selection};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::Frame;

pub(crate) use overlays::help::total_lines as help_total_lines;

/// Main render function - dispatches to appropriate view
pub fn render(frame: &mut Frame, app: &mut App) {
    crate::ui::theme::with_choice(app.runtime.config.theme, || {
        helpers::clear_area(frame, frame.area());

        // Base view
        dashboard::render(frame, app);

        // Render toast notification if present
        if app.toast.is_some() {
            overlays::toast::render(frame, app);
        }
    });
    if let Some(selection) = app.selection {
        let buffer = frame.buffer_mut();
        for (row, columns) in selected_rows(selection, buffer.area) {
            for column in columns {
                buffer[(column, row)].modifier.insert(Modifier::REVERSED);
            }
        }
    }
}

/// The text of a released mouse selection, which is then cleared.
pub fn take_selected_text(app: &mut App, buffer: &Buffer) -> Option<String> {
    let selection = app.selection.filter(|selection| selection.released)?;
    app.selection = None;
    let lines: Vec<String> = selected_rows(selection, buffer.area)
        .map(|(row, columns)| {
            let line: String = columns
                .map(|column| buffer[(column, row)].symbol())
                .collect();
            line.trim_end().to_string()
        })
        .collect();
    Some(lines.join("\n").trim().to_string()).filter(|text| !text.is_empty())
}

/// The cells between two points, row by row, as a terminal selects text.
fn selected_rows(
    selection: Selection,
    area: Rect,
) -> impl Iterator<Item = (u16, std::ops::Range<u16>)> {
    let (start, end) = if (selection.from.y, selection.from.x) <= (selection.to.y, selection.to.x) {
        (selection.from, selection.to)
    } else {
        (selection.to, selection.from)
    };
    let (start_row, end_row) = (
        start.y.max(area.top()),
        end.y.min(area.bottom().saturating_sub(1)),
    );
    let selected = selection.from != selection.to;
    (start_row..=end_row)
        .filter(move |_| selected)
        .map(move |row| {
            let first = if row == start.y { start.x } else { area.left() };
            let last = if row == end.y {
                end.x + 1
            } else {
                area.right()
            };
            (row, first.max(area.left())..last.min(area.right()))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    #[test]
    fn a_mouse_drag_copies_the_text_it_covers_across_rows() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let mut app = App::new_test();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
        let mouse = |kind, column, row| MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        };
        app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 2, 1));
        app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 10, 2));
        let frame = terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw");
        assert!(frame.buffer[(5, 1)].modifier.contains(Modifier::REVERSED));
        assert_eq!(
            take_selected_text(&mut app, frame.buffer),
            None,
            "copies only on release"
        );

        app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 10, 2));
        let frame = terminal
            .draw(|frame| render(frame, &mut app))
            .expect("draw");
        let row = |y: u16, columns: std::ops::Range<u16>| -> String {
            columns
                .map(|x| frame.buffer[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_string()
        };
        let expected = format!("{}\n{}", row(1, 2..80), row(2, 0..11))
            .trim()
            .to_string();
        assert_eq!(take_selected_text(&mut app, frame.buffer), Some(expected));
        assert!(app.selection.is_none());

        app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 4, 4));
        app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 4));
        assert!(app.selection.is_none(), "a plain click copies nothing");
    }

    #[test]
    fn fixed_theme_dashboard_never_falls_back_to_terminal_background() {
        for choice in [
            crate::ui::theme::ThemeChoice::Synthwave,
            crate::ui::theme::ThemeChoice::CatppuccinMocha,
            crate::ui::theme::ThemeChoice::Dracula,
            crate::ui::theme::ThemeChoice::Nord,
            crate::ui::theme::ThemeChoice::GruvboxDark,
            crate::ui::theme::ThemeChoice::TokyoNight,
        ] {
            let mut app = App::new_test();
            app.runtime.config.theme = choice;
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("terminal");
            terminal
                .draw(|frame| render(frame, &mut app))
                .expect("dashboard render");

            let buffer = terminal.backend().buffer();
            let reset_cells: Vec<_> = buffer
                .content
                .iter()
                .enumerate()
                .filter(|(_, cell)| cell.bg == Color::Reset)
                .map(|(index, _)| {
                    (
                        index % usize::from(buffer.area.width),
                        index / usize::from(buffer.area.width),
                    )
                })
                .take(12)
                .collect();
            assert!(
                reset_cells.is_empty(),
                "{choice:?} left cells on the terminal background at {reset_cells:?}"
            );
        }
    }
}
