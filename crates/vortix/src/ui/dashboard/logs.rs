use crate::app::App;
use crate::{constants, logger, ui::theme};
use ratatui::{
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap},
    Frame,
};

pub(super) fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.should_draw_focus(&crate::app::FocusedPanel::Logs);
    let border_style = if is_focused {
        Style::default().fg(theme::current().border_focused)
    } else {
        Style::default().fg(theme::current().border_default)
    };

    if let crate::app::state::LogsSource::Tunnel(target) = app.logs_source.clone() {
        let known = target
            .as_ref()
            .is_none_or(|id| app.runtime.profiles.iter().any(|profile| &profile.id == id));
        if known {
            render_tunnel_log(frame, app, area, border_style, target.as_ref());
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

    render_scrolled(frame, app, area, inner, &lines);
}

/// The panel body shared by both sources: wrapped lines that follow the end
/// unless the user scrolled up.
fn render_scrolled(frame: &mut Frame, app: &mut App, area: Rect, inner: Rect, lines: &[Line]) {
    let visible_lines = inner.height as usize;
    let width = usize::from(inner.width.max(1));
    // Wrapping thousands of long lines every frame made the panel crawl, so
    // only the lines on screen are wrapped. Positions come from each line's
    // width; the bottom, where the panel usually sits, is exact.
    let rows = |line: &Line| line.width().div_ceil(width).max(1);
    let total_visual_lines: usize = lines.iter().map(rows).sum();
    let max_scroll = total_visual_lines.saturating_sub(visible_lines);
    app.logs_max_scroll = u16::try_from(max_scroll).unwrap_or(u16::MAX);

    let scroll_pos = if app.logs_auto_scroll {
        max_scroll
    } else {
        (app.logs_scroll as usize).min(max_scroll)
    };

    let shown = if scroll_pos == max_scroll {
        // The last lines that fill the panel, wrapped exactly.
        let mut start = lines.len();
        let mut filled = 0;
        while start > 0 && filled < visible_lines {
            start -= 1;
            filled += Paragraph::new(lines[start].clone())
                .wrap(Wrap { trim: false })
                .line_count(inner.width);
        }
        let skip = filled.saturating_sub(visible_lines);
        Paragraph::new(lines[start..].to_vec())
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(skip).unwrap_or(u16::MAX), 0))
    } else {
        let mut start = 0;
        let mut above = 0;
        while start < lines.len() && above + rows(&lines[start]) <= scroll_pos {
            above += rows(&lines[start]);
            start += 1;
        }
        let end = (start + visible_lines + 1).min(lines.len());
        Paragraph::new(lines[start..end].to_vec())
            .wrap(Wrap { trim: false })
            .scroll((u16::try_from(scroll_pos - above).unwrap_or(u16::MAX), 0))
    };
    frame.render_widget(shown, inner);

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

/// Lines of a tunnel's log kept in memory; the rest of a long session is on disk.
const TUNNEL_LOG_TAIL: usize = 500;

fn render_tunnel_log(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    border_style: Style,
    target: Option<&crate::profile::ProfileId>,
) {
    let profile = target.and_then(|id| app.runtime.profiles.iter().find(|p| &p.id == id));
    let path = profile.and_then(|profile| match profile.protocol {
        crate::profile::ProtocolKind::OpenVpn => {
            let run_dir = app.runtime.config_dir.join(constants::OPENVPN_RUN_DIR);
            Some(crate::openvpn::runtime_log_path(
                &run_dir,
                profile.id.as_str(),
                &profile.name,
            ))
        }
        crate::profile::ProtocolKind::Mesh(driver) => Some(driver.log_path(&profile.id)),
        crate::profile::ProtocolKind::WireGuard => None,
    });
    let name = profile.map(|profile| format!("{} · {}", profile.name, profile.protocol));
    let live = target.is_some_and(|id| app.tunnel_is_active(id));
    let has_log = path
        .as_deref()
        .is_some_and(|path| refresh_tunnel_log(app, path));
    let modified = app.tunnel_log.as_ref().and_then(|cached| cached.modified);

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
        Some(name) => format!(" {name} log{session}{paused} "),
        None => format!(" VPN log{paused} "),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cached = app.tunnel_log.as_ref().filter(|_| has_log);
    let Some(cached) = cached.filter(|cached| !cached.lines.is_empty()) else {
        frame.render_widget(
            Paragraph::new("No VPN log yet. It appears once a profile connects.")
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    };
    let style = Style::default().fg(theme::current().text_primary);
    let lines: Vec<Line> = cached
        .lines
        .iter()
        .map(|line| Line::styled(line.clone(), style))
        .collect();
    render_scrolled(frame, app, area, inner, &lines);
}

/// Keep `app.tunnel_log` holding the tail of the log at `path`, re-read only
/// when its size or modification time changed. False when there is no file.
fn refresh_tunnel_log(app: &mut App, path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let modified = metadata.modified().ok();
    let fresh = app.tunnel_log.as_ref().is_some_and(|cached| {
        cached.path == path && cached.modified == modified && cached.len == metadata.len()
    });
    if !fresh {
        let Ok(text) = read_end(path, metadata.len()) else {
            return false;
        };
        let text = String::from_utf8_lossy(&text);
        let lines = text.lines().collect::<Vec<_>>();
        // A cut first line is dropped; whole lines only.
        let skip = usize::from(metadata.len() > TUNNEL_LOG_READ);
        let start = lines.len().saturating_sub(TUNNEL_LOG_TAIL).max(skip);
        app.tunnel_log = Some(crate::app::state::TunnelLogFile {
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

/// Bytes read from the end of a tunnel's log: a daemon log can grow to many
/// megabytes, and only its last lines are shown.
const TUNNEL_LOG_READ: u64 = 128 * 1024;

fn read_end(path: &std::path::Path, len: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _};
    let mut file = std::fs::File::open(path)?;
    file.seek(std::io::SeekFrom::Start(
        len.saturating_sub(TUNNEL_LOG_READ),
    ))?;
    let mut bytes = Vec::new();
    file.take(TUNNEL_LOG_READ).read_to_end(&mut bytes)?;
    Ok(bytes)
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
        crate::ui::dashboard::render_to_string(80, 8, |frame, area| super::render(frame, app, area))
    }

    fn press_f(app: &mut App, times: usize) {
        for _ in 0..times {
            app.handle_message(Message::CycleLogFilter);
        }
    }

    #[test]
    fn f_steps_through_each_active_logged_tunnel_then_back_to_events() {
        let (mut app, _dir) = app_with(&[("corp", true, 1), ("home", true, 2), ("lab", false, 3)]);
        press_f(&mut app, 4);
        assert_eq!(
            app.logs_source,
            LogsSource::Tunnel(Some(ProfileId::new("corp")))
        );
        press_f(&mut app, 1);
        assert_eq!(
            app.logs_source,
            LogsSource::Tunnel(Some(ProfileId::new("home")))
        );
        press_f(&mut app, 1);
        assert_eq!(app.logs_source, LogsSource::Events);
        assert_eq!(app.log_level_filter, None);
    }

    #[test]
    fn with_no_tunnel_up_only_the_last_connected_profile_has_a_step() {
        let (app, _dir) = app_with(&[("corp", false, 5), ("home", false, 9), ("lab", false, 0)]);
        assert_eq!(app.tunnel_log_steps(), vec![Some(ProfileId::new("home"))]);
        let (never, _dir) = app_with(&[("corp", false, 0)]);
        assert_eq!(never.tunnel_log_steps(), vec![None]);
    }

    #[test]
    fn without_logged_profiles_the_cycle_is_unchanged() {
        let (mut app, _dir) = app_with(&[]);
        press_f(&mut app, 4);
        assert_eq!(app.logs_source, LogsSource::Events);
        assert_eq!(app.log_level_filter, None);
    }

    /// A mesh network's daemon log joins the cycle like `OpenVPN`'s; `WireGuard`
    /// writes none, so it never does.
    #[test]
    fn a_netbird_network_has_its_own_log_step() {
        let (mut app, _dir) = app_with(&[("corp", true, 1)]);
        for (name, protocol) in [
            ("work", ProtocolKind::Mesh(crate::mesh::MeshDriver::NetBird)),
            ("home", ProtocolKind::WireGuard),
        ] {
            app.runtime
                .profiles
                .push(crate::config::profiles::VpnProfile {
                    id: ProfileId::new(name),
                    name: name.to_string(),
                    protocol,
                    config_path: app.runtime.config_dir.join(name),
                    location: String::new(),
                    last_used: None,
                    group: None,
                });
            let mut view = crate::app::connection::test_view(name, Phase::Up);
            view.profile_id = ProfileId::new(name);
            view.protocol = protocol;
            std::sync::Arc::make_mut(&mut app.control_snapshot)
                .tunnels
                .push(view);
        }
        assert_eq!(
            app.tunnel_log_steps(),
            vec![Some(ProfileId::new("corp")), Some(ProfileId::new("work"))]
        );
        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("work")));
        assert!(panel(&mut app).contains("work · NetBird log · LIVE"));
    }

    /// A long log is read from its end, and a line the cut splits is dropped.
    #[test]
    fn a_long_log_shows_its_last_whole_lines() {
        let (mut app, _dir) = app_with(&[("corp", true, 1)]);
        let line = "x".repeat(99);
        let body = (0..10_000)
            .flat_map(|n| [format!("{n:05}"), " ".into(), line.clone(), "\n".into()])
            .collect::<String>();
        write_log(&app, "corp", &body);
        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("corp")));
        panel(&mut app);
        let lines = &app.tunnel_log.as_ref().unwrap().lines;
        assert_eq!(lines.last().unwrap(), &format!("09999 {line}"));
        assert!(
            lines.iter().all(|kept| kept.len() == 105),
            "only whole lines"
        );
    }

    /// Only the visible lines are wrapped: following the log shows its last
    /// line, scrolled to the top its first, however long the lines are.
    #[test]
    fn a_long_log_shows_its_end_when_following_and_its_start_at_the_top() {
        let (mut app, _dir) = app_with(&[("corp", true, 1)]);
        let long = "x".repeat(150);
        let body = (0..300)
            .flat_map(|n| [format!("line-{n:03} "), long.clone(), "\n".into()])
            .collect::<String>();
        write_log(&app, "corp", &body);
        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("corp")));
        let following = panel(&mut app);
        assert!(following.contains("line-299"), "{following}");
        app.logs_auto_scroll = false;
        app.logs_scroll = 0;
        let top = panel(&mut app);
        assert!(
            top.contains("line-000") && !top.contains("line-299"),
            "{top}"
        );
    }

    #[test]
    fn the_title_says_live_then_last_session() {
        let (mut app, _dir) = app_with(&[("corp", true, 1)]);
        write_log(&app, "corp", "Initialization Sequence Completed\n");
        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("corp")));
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
        app.logs_source = LogsSource::Tunnel(None);
        assert!(panel(&mut app).contains("No VPN log yet"));

        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("gone")));
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

#[cfg(test)]
mod bench {
    use crate::app::state::LogsSource;
    use crate::app::App;
    use crate::profile::{ProfileId, ProtocolKind};
    use std::time::Instant;

    /// Not a check: prints how long the Logs panel takes on a NetBird-sized log.
    #[test]
    #[ignore = "benchmark; run with --ignored --nocapture"]
    fn bench_tunnel_log_frame() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new_test();
        app.runtime.config_dir = dir.path().to_path_buf();
        app.runtime
            .profiles
            .push(crate::config::profiles::VpnProfile {
                id: ProfileId::new("corp"),
                name: "corp".into(),
                protocol: ProtocolKind::OpenVpn,
                config_path: dir.path().join("corp.ovpn"),
                location: String::new(),
                last_used: None,
                group: None,
            });
        let run = dir.path().join(crate::constants::OPENVPN_RUN_DIR);
        std::fs::create_dir_all(&run).unwrap();
        let line = "2026-11-01T20:06:52.067+05:30 INFO [peer: +54CIu25LUP5xZiR+EAermOGSSmpkeK7rkLRIBxENSY=] client/internal/lazyconn/activity/listener_udp.go:48: created activity listener: 100.126.9.80:40665";
        let body: String = (0..4000)
            .flat_map(|n| [n.to_string(), " ".into(), line.into(), "\n".into()])
            .collect();
        let path = run.join(format!("{}.log", ProfileId::new("corp").as_str()));
        std::fs::write(&path, &body).unwrap();
        app.logs_source = LogsSource::Tunnel(Some(ProfileId::new("corp")));
        let frame = |app: &mut App| {
            crate::ui::dashboard::render_to_string(64, 20, |frame, area| {
                super::render(frame, app, area);
            })
        };
        frame(&mut app);
        let start = Instant::now();
        for _ in 0..20 {
            frame(&mut app);
        }
        println!("unchanged file: {:?}/frame", start.elapsed() / 20);
        let start = Instant::now();
        for n in 0..20 {
            std::fs::write(&path, format!("{body}{n} more\n")).unwrap();
            frame(&mut app);
        }
        println!("growing file:   {:?}/frame", start.elapsed() / 20);
    }
}
