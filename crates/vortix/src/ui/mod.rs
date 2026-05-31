//! UI rendering module

mod dashboard;
mod helpers;
/// Overlays are reachable from the App layer because the open-config
/// path pre-builds the cached `Vec<Line>` once (`CachedConfigView`)
/// instead of letting the renderer re-parse on every frame.
pub(crate) mod overlays;
mod widgets;

use crate::app::App;
use ratatui::Frame;

pub(crate) use overlays::help::total_lines as help_total_lines;

/// Main render function - dispatches to appropriate view
pub fn render(frame: &mut Frame, app: &mut App) {
    // Base view
    dashboard::render(frame, app);

    // Render toast notification if present
    if app.toast.is_some() {
        overlays::toast::render(frame, app);
    }
}
