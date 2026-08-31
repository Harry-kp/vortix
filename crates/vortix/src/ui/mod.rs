//! UI rendering module

mod dashboard;
mod helpers;
/// Overlays are reachable from the App layer because the open-config
/// path pre-builds the cached `Vec<Line>` once (`CachedConfigView`)
/// instead of letting the renderer re-parse on every frame.
pub(crate) mod overlays;
/// Single source of truth for every sigil rendered in the TUI.
/// Renderers + the `?` help overlay both read from `sigils::CATALOG`.
pub(crate) mod sigils;
mod widgets;

use crate::app::App;
use ratatui::Frame;

pub(crate) use overlays::help::total_lines as help_total_lines;

/// Main render function - dispatches to appropriate view
pub fn render(frame: &mut Frame, app: &mut App) {
    crate::theme::with_choice(app.runtime.config.theme, || {
        helpers::clear_area(frame, frame.area());

        // Base view
        dashboard::render(frame, app);

        // Render toast notification if present
        if app.toast.is_some() {
            overlays::toast::render(frame, app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    #[test]
    fn fixed_theme_dashboard_never_falls_back_to_terminal_background() {
        for choice in [
            crate::theme::ThemeChoice::Synthwave,
            crate::theme::ThemeChoice::CatppuccinMocha,
            crate::theme::ThemeChoice::Dracula,
            crate::theme::ThemeChoice::Nord,
            crate::theme::ThemeChoice::GruvboxDark,
            crate::theme::ThemeChoice::TokyoNight,
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
