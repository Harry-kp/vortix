//! Keyboard and mouse event handling for the TUI.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::{App, AuthField, FocusedPanel, InputMode, ToastType};
use crate::constants;
use crate::message::{self, Message, ScrollMove, SelectionMove};
use crate::state::help_max_scroll_for_terminal_height;

enum ConfirmAction {
    Confirmed,
    Cancelled,
    None,
}

/// Shared logic for all Yes/No confirmation dialogs.
fn handle_confirm_keys(key: KeyEvent, confirm_selected: &mut bool) -> ConfirmAction {
    match key.code {
        KeyCode::Tab => {
            *confirm_selected = !*confirm_selected;
            ConfirmAction::None
        }
        KeyCode::Left | KeyCode::Char('h') => {
            *confirm_selected = true;
            ConfirmAction::None
        }
        KeyCode::Right | KeyCode::Char('l') => {
            *confirm_selected = false;
            ConfirmAction::None
        }
        KeyCode::Char('y' | 'Y') => ConfirmAction::Confirmed,
        KeyCode::Char('n' | 'N') | KeyCode::Esc => ConfirmAction::Cancelled,
        KeyCode::Enter => {
            if *confirm_selected {
                ConfirmAction::Confirmed
            } else {
                ConfirmAction::Cancelled
            }
        }
        _ => ConfirmAction::None,
    }
}

impl App {
    #[allow(clippy::too_many_lines)]
    pub fn handle_key(&mut self, key: KeyEvent) {
        // 1. Global: Quit
        // Ctrl+C always force-quits.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.handle_message(Message::Quit);
            return;
        }
        // 'q' in normal mode: exit immediately. Active VPN sessions persist.
        if key.code == KeyCode::Char('q') && self.input_mode == InputMode::Normal {
            self.handle_message(Message::Quit);
            return;
        }

        // 2. Dismiss toast on Esc
        if key.code == KeyCode::Esc && self.toast.is_some() {
            self.toast = None;
            return;
        }

        // 3. Global: Handle Config View - scroll or close
        if self.show_config {
            match key.code {
                KeyCode::Esc | KeyCode::Char('v') => {
                    self.handle_message(Message::CloseOverlay);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.handle_message(Message::Scroll(ScrollMove::Up));
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.handle_message(Message::Scroll(ScrollMove::Down));
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.handle_message(Message::Scroll(ScrollMove::Top));
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.handle_message(Message::Scroll(ScrollMove::Bottom));
                }
                _ => {} // Ignore other keys
            }
            return;
        }

        // 4. Global: Handle Action Menu
        if self.show_action_menu || self.show_bulk_menu {
            self.handle_action_menu_keys(key);
            return;
        }

        // Handle based on Input Mode
        let input_mode = self.input_mode.clone();
        match input_mode {
            InputMode::Import {
                mut path,
                mut cursor,
            } => {
                self.handle_input_import(key, &mut path, &mut cursor);
                if let InputMode::Import { .. } = self.input_mode {
                    self.input_mode = InputMode::Import { path, cursor };
                }
            }
            InputMode::AuthPrompt {
                profile_idx,
                profile_name,
                mut username,
                mut username_cursor,
                mut password,
                mut password_cursor,
                mut focused_field,
                mut save_credentials,
                connect_after,
            } => {
                self.handle_input_auth(
                    key,
                    profile_idx,
                    &profile_name,
                    &mut username,
                    &mut username_cursor,
                    &mut password,
                    &mut password_cursor,
                    &mut focused_field,
                    &mut save_credentials,
                    connect_after,
                );
                // Update state if still in AuthPrompt mode
                if let InputMode::AuthPrompt { .. } = self.input_mode {
                    self.input_mode = InputMode::AuthPrompt {
                        profile_idx,
                        profile_name,
                        username,
                        username_cursor,
                        password,
                        password_cursor,
                        focused_field,
                        save_credentials,
                        connect_after,
                    };
                }
            }
            InputMode::DependencyError { .. } | InputMode::PermissionDenied { .. } => {
                if key.code == KeyCode::Esc {
                    self.handle_message(Message::CloseOverlay);
                }
            }
            InputMode::Help { mut scroll } => {
                let max_scroll = help_max_scroll_for_terminal_height(
                    self.terminal_size.1,
                    crate::ui::help_total_lines(),
                );
                scroll = scroll.min(max_scroll);
                match key.code {
                    KeyCode::Esc | KeyCode::Char('?' | 'q') => {
                        self.handle_message(Message::CloseOverlay);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        scroll = scroll.saturating_add(1).min(max_scroll);
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        scroll = scroll.saturating_sub(1);
                    }
                    KeyCode::Char('g') | KeyCode::Home => {
                        scroll = 0;
                    }
                    KeyCode::Char('G') | KeyCode::End => {
                        scroll = max_scroll;
                    }
                    _ => {}
                }
                if let InputMode::Help { .. } = self.input_mode {
                    self.input_mode = InputMode::Help { scroll };
                }
            }
            InputMode::Rename {
                index,
                mut new_name,
                mut cursor,
            } => {
                self.handle_rename_keys(key, index, &mut new_name, &mut cursor);
                if let InputMode::Rename { .. } = self.input_mode {
                    self.input_mode = InputMode::Rename {
                        index,
                        new_name,
                        cursor,
                    };
                }
            }
            InputMode::Search {
                mut query,
                mut cursor,
            } => {
                self.handle_search_keys(key, &mut query, &mut cursor);
                if let InputMode::Search { .. } = self.input_mode {
                    self.input_mode = InputMode::Search { query, cursor };
                }
            }
            InputMode::ConfirmDelete {
                mut confirm_selected,
                ..
            } => match handle_confirm_keys(key, &mut confirm_selected) {
                ConfirmAction::Confirmed => self.handle_message(Message::ConfirmDelete),
                ConfirmAction::Cancelled => self.handle_message(Message::CloseOverlay),
                ConfirmAction::None => {
                    if let InputMode::ConfirmDelete {
                        confirm_selected: cs,
                        ..
                    } = &mut self.input_mode
                    {
                        *cs = confirm_selected;
                    }
                }
            },
            InputMode::ConfirmSwitch {
                to_idx,
                mut confirm_selected,
                ..
            } => match handle_confirm_keys(key, &mut confirm_selected) {
                ConfirmAction::Confirmed => {
                    self.handle_message(Message::ConfirmSwitch { idx: to_idx });
                }
                ConfirmAction::Cancelled => self.handle_message(Message::CloseOverlay),
                ConfirmAction::None => {
                    if let InputMode::ConfirmSwitch {
                        confirm_selected: cs,
                        ..
                    } = &mut self.input_mode
                    {
                        *cs = confirm_selected;
                    }
                }
            },
            InputMode::Normal => self.handle_normal_keys(key),
        }
    }

    pub fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) {
        use crossterm::event::{MouseButton, MouseEventKind};

        // When an overlay is active, only route scroll to the overlay — don't
        // let mouse events pass through to panels behind it.
        if self.input_mode != InputMode::Normal {
            match (&mut self.input_mode, mouse.kind) {
                (InputMode::Help { scroll }, MouseEventKind::ScrollDown) => {
                    let max_scroll = help_max_scroll_for_terminal_height(
                        self.terminal_size.1,
                        crate::ui::help_total_lines(),
                    );
                    *scroll = (*scroll).min(max_scroll);
                    *scroll = scroll.saturating_add(3).min(max_scroll);
                }
                (InputMode::Help { scroll }, MouseEventKind::ScrollUp) => {
                    let max_scroll = help_max_scroll_for_terminal_height(
                        self.terminal_size.1,
                        crate::ui::help_total_lines(),
                    );
                    *scroll = (*scroll).min(max_scroll);
                    *scroll = scroll.saturating_sub(3);
                }
                _ => {}
            }
            return;
        }

        if self.show_config {
            match mouse.kind {
                MouseEventKind::ScrollDown => self.scroll_down(),
                MouseEventKind::ScrollUp => self.scroll_up(),
                _ => {}
            }
            return;
        }

        if self.show_action_menu || self.show_bulk_menu {
            return;
        }

        match mouse.kind {
            MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                let hovered = self.panel_at(mouse.column, mouse.row);
                let original = self.focused_panel.clone();
                if let Some(panel) = hovered {
                    self.focused_panel = panel;
                }
                match mouse.kind {
                    MouseEventKind::ScrollDown => {
                        self.handle_message(Message::Scroll(ScrollMove::Down));
                    }
                    MouseEventKind::ScrollUp => {
                        self.handle_message(Message::Scroll(ScrollMove::Up));
                    }
                    _ => unreachable!(),
                }
                self.focused_panel = original;
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(panel) = self.panel_at(mouse.column, mouse.row) {
                    self.handle_message(Message::FocusPanel(panel.clone()));

                    if matches!(panel, crate::app::FocusedPanel::Sidebar)
                        && !self.profiles.is_empty()
                    {
                        if let Some(area) = self.panel_areas.get(&crate::app::FocusedPanel::Sidebar)
                        {
                            let inner_y = area.y + 1; // skip top border
                            let inner_h = area.height.saturating_sub(2);
                            if mouse.row >= inner_y && mouse.row < inner_y + inner_h {
                                let row_in_view = (mouse.row - inner_y) as usize;
                                let scroll_offset = self.profile_list_state.offset();
                                let idx = scroll_offset + row_in_view;
                                if idx < self.profiles.len() {
                                    self.profile_list_state.select(Some(idx));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_input_import(&mut self, key: KeyEvent, path: &mut String, cursor: &mut usize) {
        match key.code {
            KeyCode::Esc => self.handle_message(Message::CloseOverlay),
            KeyCode::Enter => {
                let path_clone = path.clone();
                self.handle_message(Message::Import(path_clone));
            }
            _ => Self::handle_text_field_input(key, path, cursor),
        }
    }

    /// Handle keyboard input for the auth credentials overlay.
    #[allow(clippy::too_many_arguments)]
    fn handle_input_auth(
        &mut self,
        key: KeyEvent,
        profile_idx: usize,
        _profile_name: &str,
        username: &mut String,
        username_cursor: &mut usize,
        password: &mut String,
        password_cursor: &mut usize,
        focused_field: &mut AuthField,
        save_credentials: &mut bool,
        connect_after: bool,
    ) {
        match key.code {
            KeyCode::Esc => self.handle_message(Message::CloseOverlay),
            KeyCode::Tab | KeyCode::BackTab => {
                // Cycle through fields: Username -> Password -> SaveCheckbox -> Username
                *focused_field = match (&focused_field, key.code) {
                    (AuthField::Username, KeyCode::Tab)
                    | (AuthField::SaveCheckbox, KeyCode::BackTab) => AuthField::Password,
                    (AuthField::Password, KeyCode::Tab)
                    | (AuthField::Username, KeyCode::BackTab) => AuthField::SaveCheckbox,
                    (AuthField::SaveCheckbox, KeyCode::Tab)
                    | (AuthField::Password, KeyCode::BackTab) => AuthField::Username,
                    _ => focused_field.clone(),
                };
            }
            KeyCode::Enter => {
                // On SaveCheckbox, toggle the checkbox instead of submitting
                if *focused_field == AuthField::SaveCheckbox {
                    *save_credentials = !*save_credentials;
                    return;
                }
                // Require both fields to be non-empty
                if username.is_empty() || password.is_empty() {
                    self.show_toast(
                        "Both username and password are required".to_string(),
                        ToastType::Warning,
                    );
                    return;
                }
                self.handle_message(Message::AuthSubmit {
                    idx: profile_idx,
                    username: username.clone(),
                    password: password.clone(),
                    save: *save_credentials,
                    connect_after,
                });
            }
            KeyCode::Char(' ') if *focused_field == AuthField::SaveCheckbox => {
                *save_credentials = !*save_credentials;
            }
            _ => {
                // Route text editing to the focused field
                let (text, cursor) = match focused_field {
                    AuthField::Username => (username, username_cursor),
                    AuthField::Password => (password, password_cursor),
                    AuthField::SaveCheckbox => return, // No text editing on checkbox
                };
                Self::handle_text_field_input(key, text, cursor);
            }
        }
    }

    /// Generic text field input handler for cursor movement and editing.
    ///
    /// `cursor` tracks the **character position** (not byte offset) so that
    /// multi-byte UTF-8 characters (é, ñ, 日本語, emoji) work correctly.
    pub(super) fn handle_text_field_input(key: KeyEvent, text: &mut String, cursor: &mut usize) {
        let char_count = text.chars().count();

        match key.code {
            KeyCode::Left => {
                *cursor = cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                if *cursor < char_count {
                    *cursor += 1;
                }
            }
            KeyCode::Home => {
                *cursor = 0;
            }
            KeyCode::End => {
                *cursor = char_count;
            }
            KeyCode::Backspace => {
                if *cursor > 0 {
                    let byte_idx = text.char_indices().nth(*cursor - 1).map_or(0, |(i, _)| i);
                    text.remove(byte_idx);
                    *cursor -= 1;
                }
            }
            KeyCode::Delete => {
                if *cursor < char_count {
                    let byte_idx = text
                        .char_indices()
                        .nth(*cursor)
                        .map_or(text.len(), |(i, _)| i);
                    text.remove(byte_idx);
                }
            }
            KeyCode::Char(c) => {
                let byte_idx = text
                    .char_indices()
                    .nth(*cursor)
                    .map_or(text.len(), |(i, _)| i);
                text.insert(byte_idx, c);
                *cursor += 1;
            }
            _ => {}
        }
    }

    fn handle_normal_keys(&mut self, key: KeyEvent) {
        match key.code {
            // Global Toggles
            KeyCode::Tab | KeyCode::Char('l') => {
                if self.zoomed_panel.is_none() {
                    self.handle_message(Message::NextPanel);
                }
            }
            KeyCode::BackTab | KeyCode::Char('h') => {
                if self.zoomed_panel.is_none() {
                    self.handle_message(Message::PreviousPanel);
                }
            }

            // Expert Mode: Zoom / Flip
            KeyCode::Char('z') => self.handle_message(Message::ToggleZoom),
            KeyCode::Char('f')
                if matches!(
                    self.focused_panel,
                    FocusedPanel::Chart | FocusedPanel::ConnectionDetails | FocusedPanel::Security
                ) =>
            {
                self.handle_message(Message::ToggleFlip);
            }
            KeyCode::Char('x') => self.handle_message(Message::OpenActionMenu),
            KeyCode::Char('b') => self.handle_message(Message::OpenBulkMenu),
            KeyCode::Esc => {
                if self.zoomed_panel.is_some() {
                    self.zoomed_panel = None;
                }
            }

            KeyCode::Home | KeyCode::Char('g') if self.focused_panel != FocusedPanel::Logs => {
                self.handle_message(Message::ProfileMove(SelectionMove::First));
            }
            KeyCode::End | KeyCode::Char('G') if self.focused_panel != FocusedPanel::Logs => {
                self.handle_message(Message::ProfileMove(SelectionMove::Last));
            }
            KeyCode::PageUp => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                let next = current.saturating_sub(constants::PROFILE_LIST_PAGE_SIZE);
                self.profile_list_state.select(Some(next));
            }
            KeyCode::PageDown => {
                let current = self.profile_list_state.selected().unwrap_or(0);
                let last = self.profiles.len().saturating_sub(1);
                let next = (current + constants::PROFILE_LIST_PAGE_SIZE).min(last);
                self.profile_list_state.select(Some(next));
            }

            // Quick Actions (always available)
            KeyCode::Char('1') => self.handle_message(Message::QuickConnect(0)),
            KeyCode::Char('2') => self.handle_message(Message::QuickConnect(1)),
            KeyCode::Char('3') => self.handle_message(Message::QuickConnect(2)),
            KeyCode::Char('4') => self.handle_message(Message::QuickConnect(3)),
            KeyCode::Char('5') => self.handle_message(Message::QuickConnect(4)),
            KeyCode::Char('6') => self.handle_message(Message::QuickConnect(5)),
            KeyCode::Char('7') => self.handle_message(Message::QuickConnect(6)),
            KeyCode::Char('8') => self.handle_message(Message::QuickConnect(7)),
            KeyCode::Char('9') => self.handle_message(Message::QuickConnect(8)),
            KeyCode::Char('d') => self.handle_message(Message::Disconnect),
            KeyCode::Char('r') => {
                if self.focused_panel == FocusedPanel::Sidebar {
                    self.handle_message(Message::ConnectSelected);
                } else {
                    self.handle_message(Message::Reconnect);
                }
            }
            KeyCode::Char('i') => self.handle_message(Message::OpenImport),
            KeyCode::Char('y') => self.handle_message(Message::CopyIp),

            KeyCode::F(1) => self.handle_message(Message::FocusPanel(FocusedPanel::Sidebar)),
            KeyCode::F(2) => {
                self.handle_message(Message::FocusPanel(FocusedPanel::ConnectionDetails));
            }
            KeyCode::F(3) => self.handle_message(Message::FocusPanel(FocusedPanel::Chart)),
            KeyCode::F(4) => self.handle_message(Message::FocusPanel(FocusedPanel::Security)),
            KeyCode::F(5) => self.handle_message(Message::FocusPanel(FocusedPanel::Logs)),

            KeyCode::Char('K') => self.handle_message(Message::ToggleKillSwitch),
            KeyCode::Char('?') => self.handle_message(Message::OpenHelp),
            KeyCode::Char('/') => self.handle_message(Message::OpenSearch),

            _ => self.handle_panel_keys(key),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_panel_keys(&mut self, key: KeyEvent) {
        match self.focused_panel {
            FocusedPanel::Sidebar => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    self.handle_message(Message::ProfileMove(SelectionMove::Next));
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.handle_message(Message::ProfileMove(SelectionMove::Prev));
                }
                KeyCode::Char('x') => self.handle_message(Message::OpenActionMenu),
                KeyCode::Char('b') => self.handle_message(Message::OpenBulkMenu),
                KeyCode::Delete | KeyCode::Backspace => {
                    self.handle_message(Message::OpenDelete(None));
                }
                KeyCode::Char('c') | KeyCode::Enter => {
                    self.handle_message(Message::ToggleConnect(None));
                }
                KeyCode::Char('v') => {
                    if self.profile_list_state.selected().is_some() {
                        self.handle_message(Message::OpenConfig);
                    } else {
                        self.show_toast(
                            "Select a profile to view its config".to_string(),
                            ToastType::Info,
                        );
                    }
                }
                KeyCode::Char('s') => self.handle_message(Message::CycleSortOrder),
                KeyCode::Char('a') => self.handle_message(Message::ManageAuth),
                KeyCode::Char('A') => self.handle_message(Message::ClearAuth),
                KeyCode::Char('R') => self.handle_message(Message::OpenRename),
                _ => {}
            },
            FocusedPanel::Logs => {
                // Activity Log navigation (scroll through log history)
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.logs_auto_scroll = false;
                        self.logs_scroll = self.logs_scroll.saturating_sub(1);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if self.logs_scroll < self.logs_max_scroll {
                            self.logs_scroll = self.logs_scroll.saturating_add(1);
                        }
                        if self.logs_scroll
                            >= self
                                .logs_max_scroll
                                .saturating_sub(constants::LOGS_AUTO_SCROLL_THRESHOLD)
                        {
                            self.logs_auto_scroll = true;
                        }
                    }
                    KeyCode::End | KeyCode::Char('G') => {
                        // Jump to end and re-enable auto-scroll
                        self.logs_auto_scroll = true;
                    }
                    KeyCode::Home | KeyCode::Char('g') => {
                        // Jump to start
                        self.logs_auto_scroll = false;
                        self.logs_scroll = 0;
                    }
                    KeyCode::Char('f') => self.handle_message(Message::CycleLogFilter),
                    KeyCode::Char('L') => self.handle_message(Message::ClearLogs),
                    _ => {}
                }
            }
            // Read-only panels
            FocusedPanel::ConnectionDetails | FocusedPanel::Chart | FocusedPanel::Security => {}
        }
    }

    /// Handle keys when the action menu is open
    fn handle_action_menu_keys(&mut self, key: KeyEvent) {
        let actions = if self.show_bulk_menu {
            message::get_bulk_actions()
        } else {
            message::get_single_actions(&self.focused_panel)
        };
        let action_count = actions.len();

        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'x' | 'b') => {
                self.handle_message(Message::CloseOverlay);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(current) = self.action_menu_state.selected() {
                    if current > 0 {
                        self.action_menu_state.select(Some(current - 1));
                    } else {
                        self.action_menu_state.select(Some(action_count - 1));
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(current) = self.action_menu_state.selected() {
                    if current < action_count - 1 {
                        self.action_menu_state.select(Some(current + 1));
                    } else {
                        self.action_menu_state.select(Some(0));
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(selected) = self.action_menu_state.selected() {
                    if let Some(item) = actions.get(selected) {
                        let msg = item.message.clone();
                        self.show_action_menu = false;
                        self.show_bulk_menu = false;
                        self.handle_message(msg);
                    }
                }
            }
            KeyCode::Char(c) => {
                // Try exact (case-sensitive) match first, fall back to case-insensitive.
                // This allows a/A to be distinct keys while keeping i/I convenience.
                let item = actions
                    .iter()
                    .find(|a| a.key.len() == 1 && a.key.starts_with(c))
                    .or_else(|| {
                        actions.iter().find(|a| {
                            a.key.len() == 1
                                && a.key
                                    .chars()
                                    .next()
                                    .is_some_and(|kc| kc.eq_ignore_ascii_case(&c))
                        })
                    });
                if let Some(item) = item {
                    let msg = item.message.clone();
                    self.show_action_menu = false;
                    self.show_bulk_menu = false;
                    self.handle_message(msg);
                }
            }
            KeyCode::Delete | KeyCode::Backspace => {
                if let Some(item) = actions.iter().find(|a| a.key == "DEL") {
                    let msg = item.message.clone();
                    self.show_action_menu = false;
                    self.show_bulk_menu = false;
                    self.handle_message(msg);
                }
            }
            _ => {}
        }
    }

    fn handle_rename_keys(
        &mut self,
        key: KeyEvent,
        index: usize,
        new_name: &mut String,
        cursor: &mut usize,
    ) {
        match key.code {
            KeyCode::Esc => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Enter => {
                let trimmed = new_name.trim().to_string();
                if !trimmed.is_empty() {
                    self.rename_profile(index, &trimmed);
                }
                self.input_mode = InputMode::Normal;
            }
            _ => Self::handle_text_field_input(key, new_name, cursor),
        }
    }

    fn handle_search_keys(&mut self, key: KeyEvent, query: &mut String, cursor: &mut usize) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.input_mode = InputMode::Normal;
            }
            KeyCode::Backspace | KeyCode::Delete | KeyCode::Char(_) => {
                Self::handle_text_field_input(key, query, cursor);
                self.apply_search_filter(query);
            }
            _ => Self::handle_text_field_input(key, query, cursor),
        }
    }

    pub(crate) fn apply_search_filter(&mut self, query: &str) {
        if query.is_empty() {
            self.search_match_count = self.profiles.len();
            self.profile_list_state.select(Some(0));
            return;
        }
        let lower = query.to_lowercase();
        let matches: Vec<usize> = self
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, p)| p.name.to_lowercase().contains(&lower))
            .map(|(i, _)| i)
            .collect();
        self.search_match_count = matches.len();
        if let Some(&first) = matches.first() {
            self.profile_list_state.select(Some(first));
        }
    }
}
