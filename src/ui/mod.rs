//! UI rendering module

mod dashboard;
mod overlays;
mod widgets;

use crate::app::App;
use ratatui::Frame;

/// Main render function - dispatches to appropriate view
pub fn render(frame: &mut Frame, app: &mut App) {
    // Render base view
    // Unified view
    dashboard::render(frame, app);

    // Render Help overlay if active
    if app.show_help {
        overlays::help::render(frame, app);
    }

    // Render toast notification if present
    if app.toast.is_some() {
        overlays::toast::render(frame, app);
    }
}
