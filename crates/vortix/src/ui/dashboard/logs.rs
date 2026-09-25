use crate::app::App;
use crate::{constants, logger, ui::theme};
use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
    Frame,
};

#[allow(clippy::too_many_lines)]
pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Logs);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };

    if let crate::app::state::LogsSource::OpenVpn(target) = app.logs_source.clone() {
        let known = target
            .as_ref()
            .is_none_or(|id| app.runtime.profiles.iter().any(|profile| &profile.id == id));
        if known {
            render_openvpn(frame, app, area, border_style, target.as_ref());
            return;
        }
        // The profile was deleted while its log was on screen.
        app.logs_source = crate::app::state::LogsSource::Events;
    }

    let filter_label = match app.log_level_filter {
        Some(logger::LogLevel::Error) => " Err",
        Some(logger::LogLevel::Warning) => " Warn+",
        Some(logger::LogLevel::Info) => " Info+",
        None | Some(_) => "",
    };

    let title = event_log_title(app.logs_auto_scroll, filter_label);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let raw_logs = logger::get_logs();
    let all_logs: Vec<_> = if let Some(min_level) = app.log_level_filter {
        raw_logs
            .into_iter()
            .filter(|e| e.level >= min_level)
            .collect()
    } else {
        raw_logs
    };

    if all_logs.is_empty() {
        frame.render_widget(
            Paragraph::new("No activity yet").alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let lines: Vec<Line> = all_logs
        .iter()
        .map(|entry| {
            let time_str = crate::ui::helpers::format_system_time_local(entry.timestamp);
            let level_tag = entry.level.prefix();

            let cat = format!(
                "{:<width$}",
                entry.category,
                width = constants::LOG_CATEGORY_WIDTH
            );

            let level_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::current().error),
                logger::LogLevel::Warning => Style::default().fg(theme::current().warning),
                logger::LogLevel::Info => Style::default().fg(theme::current().nord_frost_3),
                logger::LogLevel::Debug => Style::default().fg(theme::current().inactive),
            };

            let msg_style = match entry.level {
                logger::LogLevel::Error => Style::default().fg(theme::current().error),
                logger::LogLevel::Warning => Style::default().fg(theme::current().warning),
                logger::LogLevel::Info => {
                    if entry.message.contains("Connected") || entry.message.contains("secure") {
                        Style::default().fg(theme::current().success)
                    } else {
                        Style::default().fg(theme::current().inactive)
                    }
                }
                logger::LogLevel::Debug => Style::default().fg(theme::current().inactive),
            };

            Line::from(vec![
                Span::styled(
                    format!("[{time_str}] "),
                    Style::default().fg(theme::current().text_secondary),
                ),
                Span::styled(format!("{level_tag} "), level_style),
                Span::styled(
                    format!("{cat}  "),
                    Style::default().fg(theme::current().nord_polar_night_4),
                ),
                Span::styled(entry.message.clone(), msg_style),
            ])
        })
        .collect();

    render_scrolled(frame, app, area, inner, lines);
}

/// The panel body shared by both sources: wrapped lines that follow the end
/// unless the user scrolled up.
fn render_scrolled(frame: &mut Frame, app: &mut App, area: Rect, inner: Rect, lines: Vec<Line>) {
    let visible_lines = inner.height as usize;
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });

    let total_visual_lines = paragraph.line_count(inner.width);
    let max_scroll = total_visual_lines.saturating_sub(visible_lines);
    app.logs_max_scroll = u16::try_from(max_scroll).unwrap_or(u16::MAX);

    let scroll_pos = if app.logs_auto_scroll {
        max_scroll
    } else {
        (app.logs_scroll as usize).min(max_scroll)
    };

    #[allow(clippy::cast_possible_truncation)]
    let paragraph = paragraph.scroll((scroll_pos as u16, 0));

    frame.render_widget(paragraph, inner);

    // Scrollbar
    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("↑"))
        .end_symbol(Some("↓"))
        .style(Style::default().fg(theme::current().nord_polar_night_4))
        .thumb_style(Style::default().fg(theme::current().accent_primary));

    let mut scrollbar_state = ScrollbarState::new(max_scroll).position(scroll_pos);

    frame.render_stateful_widget(
        scrollbar,
        area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

/// Lines of an `OpenVPN` log kept in memory; the rest of a long session is on disk.
const OPENVPN_LOG_TAIL: usize = 2000;

fn render_openvpn(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    border_style: Style,
    target: Option<&crate::profile::ProfileId>,
) {
    let profile = target.and_then(|id| app.runtime.profiles.iter().find(|p| &p.id == id));
    let path = profile.map(|profile| {
        let run_dir = app.runtime.config_dir.join(constants::OPENVPN_RUN_DIR);
        crate::openvpn::runtime_log_path(&run_dir, profile.id.as_str(), &profile.name)
    });
    let name = profile.map(|profile| profile.name.clone());
    let live = target.is_some_and(|id| app.tunnel_is_active(id));
    let has_log = path
        .as_deref()
        .is_some_and(|path| refresh_openvpn_log(app, path));
    let modified = app.openvpn_log.as_ref().and_then(|cached| cached.modified);

    let session = match (has_log, live) {
        (_, true) => " · LIVE".to_string(),
        (true, false) => modified.map_or_else(
            || " · last session".to_string(),
            |ended| {
                format!(
                    " · last session, ended {}",
                    crate::ui::helpers::format_system_time_local(ended)
                )
            },
        ),
        (false, false) => String::new(),
    };
    let paused = if app.logs_auto_scroll {
        ""
    } else {
        " [Paused]"
    };
    let title = match name {
        Some(name) => format!(" {name} · OpenVPN log{session}{paused} "),
        None => format!(" OpenVPN log{paused} "),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cached = app.openvpn_log.as_ref().filter(|_| has_log);
    let Some(cached) = cached.filter(|cached| !cached.lines.is_empty()) else {
        frame.render_widget(
            Paragraph::new("No OpenVPN log yet. It appears after an OpenVPN profile connects.")
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };
    let style = Style::default().fg(theme::current().text_primary);
    let lines = cached
        .lines
        .iter()
        .map(|line| Line::styled(line.clone(), style))
        .collect();
    render_scrolled(frame, app, area, inner, lines);
}

/// Keep `app.openvpn_log` holding the tail of the log at `path`, re-read only
/// when its size or modification time changed. False when there is no file.
fn refresh_openvpn_log(app: &mut App, path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let modified = metadata.modified().ok();
    let fresh = app.openvpn_log.as_ref().is_some_and(|cached| {
        cached.path == path && cached.modified == modified && cached.len == metadata.len()
    });
    if !fresh {
        let Ok(text) = std::fs::read(path) else {
            return false;
        };
        let text = String::from_utf8_lossy(&text);
        let lines = text.lines().collect::<Vec<_>>();
        let start = lines.len().saturating_sub(OPENVPN_LOG_TAIL);
        app.openvpn_log = Some(crate::app::state::OpenVpnLogFile {
            path: path.to_path_buf(),
            modified,
            len: metadata.len(),
            lines: lines[start..]
                .iter()
                .map(|line| (*line).to_string())
                .collect(),
        });
    }
    true
}

fn event_log_title(auto_scroll: bool, filter_label: &str) -> String {
    let state = if auto_scroll { "Live" } else { "Paused" };
    format!(" Event Log [{state}{filter_label}] ")
}

#[cfg(test)]
mod tests {
    use crate::app::state::LogsSource;
    use crate::app::App;
    use crate::control::{Phase, Snapshot};
    use crate::message::Message;
    use crate::profile::{ProfileId, ProtocolKind};
    use ratatui::{backend::TestBackend, Terminal};
    use std::time::{Duration, SystemTime};

    /// `OpenVPN` profiles `(name, active, last_used seconds)` in a scratch config dir.
    fn app_with(profiles: &[(&str, bool, u64)]) -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new_test();
        app.runtime.config_dir = dir.path().to_path_buf();
        let mut snapshot = Snapshot::default();
        for (name, active, used) in profiles {
            app.runtime
                .profiles
                .push(crate::config::profiles::VpnProfile {
                    id: ProfileId::new(*name),
                    name: (*name).to_string(),
                    protocol: ProtocolKind::OpenVpn,
                    config_path: dir.path().join(format!("{name}.ovpn")),
                    location: String::new(),
                    last_used: (*used > 0)
                        .then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(*used)),
                    group: None,
                });
            if *active {
                let mut view = crate::app::connection::test_view(name, Phase::Up);
                view.profile_id = ProfileId::new(*name);
                view.protocol = ProtocolKind::OpenVpn;
                snapshot.tunnels.push(view);
            }
        }
        app.control_snapshot = std::sync::Arc::new(snapshot);
        (app, dir)
    }

    fn write_log(app: &App, name: &str, text: &str) {
        let run = app
            .runtime
            .config_dir
            .join(crate::constants::OPENVPN_RUN_DIR);
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(
            run.join(format!("{}.log", ProfileId::new(name).as_str())),
            text,
        )
        .unwrap();
    }

    fn panel(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
        terminal
            .draw(|frame| super::render(frame, app, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn press_f(app: &mut App, times: usize) {
        for _ in 0..times {
            app.handle_message(Message::CycleLogFilter);
        }
    }

    #[test]
    fn f_steps_through_each_active_openvpn_tunnel_then_back_to_events() {
        let (mut app, _dir) = app_with(&[("corp", true, 1), ("home", true, 2), ("lab", false, 3)]);
        press_f(&mut app, 4);
        assert_eq!(
            app.logs_source,
            LogsSource::OpenVpn(Some(ProfileId::new("corp")))
        );
        press_f(&mut app, 1);
        assert_eq!(
            app.logs_source,
            LogsSource::OpenVpn(Some(ProfileId::new("home")))
        );
        press_f(&mut app, 1);
        assert_eq!(app.logs_source, LogsSource::Events);
        assert_eq!(app.log_level_filter, None);
    }

    #[test]
    fn with_no_tunnel_up_only_the_last_connected_profile_has_a_step() {
        let (app, _dir) = app_with(&[("corp", false, 5), ("home", false, 9), ("lab", false, 0)]);
        assert_eq!(app.openvpn_log_steps(), vec![Some(ProfileId::new("home"))]);
        let (never, _dir) = app_with(&[("corp", false, 0)]);
        assert_eq!(never.openvpn_log_steps(), vec![None]);
    }

    #[test]
    fn without_openvpn_profiles_the_cycle_is_unchanged() {
        let (mut app, _dir) = app_with(&[]);
        press_f(&mut app, 4);
        assert_eq!(app.logs_source, LogsSource::Events);
        assert_eq!(app.log_level_filter, None);
    }

    #[test]
    fn the_title_says_live_then_last_session() {
        let (mut app, _dir) = app_with(&[("corp", true, 1)]);
        write_log(&app, "corp", "Initialization Sequence Completed\n");
        app.logs_source = LogsSource::OpenVpn(Some(ProfileId::new("corp")));
        let live = panel(&mut app);
        assert!(live.contains("corp · OpenVPN log · LIVE"), "{live}");
        assert!(live.contains("Initialization Sequence Completed"), "{live}");

        app.control_snapshot = std::sync::Arc::new(Snapshot::default());
        let ended = panel(&mut app);
        assert!(
            ended.contains("corp · OpenVPN log · last session, ended"),
            "{ended}"
        );
        assert!(
            ended.contains("Initialization Sequence Completed"),
            "{ended}"
        );
    }

    #[test]
    fn a_missing_log_says_so_and_a_deleted_profile_returns_to_events() {
        let (mut app, _dir) = app_with(&[("corp", false, 0)]);
        app.logs_source = LogsSource::OpenVpn(None);
        assert!(panel(&mut app).contains("No OpenVPN log yet"));

        app.logs_source = LogsSource::OpenVpn(Some(ProfileId::new("gone")));
        let body = panel(&mut app);
        assert_eq!(app.logs_source, LogsSource::Events);
        assert!(body.contains("Event Log"), "{body}");
    }

    #[test]
    fn event_log_title_does_not_advertise_dormant_background_actions() {
        let title = super::event_log_title(true, "");

        assert_eq!(title, " Event Log [Live] ");
        assert!(!title.contains("Background"));
        assert!(!title.contains("b→G"));
    }
}
