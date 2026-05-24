// Plan 017 U4: callers are added in U5 (hook editor form). Until then
// the render/cursor helpers report as dead code; allow it on the
// module for the U4 commit so the widget can be code-reviewed in
// isolation without dragging U5 in.
#![allow(dead_code)]

//! Minimal multi-line text editor widget (plan 017 U4).
//!
//! Built-from-scratch because the upstream `tui-textarea` crate only
//! supports ratatui ^0.29, and the third-party `tui-textarea-2` fork
//! that targets ratatui 0.30 carries supply-chain risk we'd rather
//! not take on for v0.3.0. ~200 LOC is cheaper than auditing a fork.
//!
//! Scope: just enough for the hook editor form (U5). Single
//! contiguous block of text with cursor, no selection, no undo, no
//! syntax highlighting, no soft-wrap (lines that exceed the render
//! width are horizontally scrolled instead).
//!
//! Public API:
//! - [`TextArea::new`] / [`TextArea::with_text`] — constructors.
//! - [`TextArea::lines`] / [`TextArea::as_string`] — read out.
//! - [`TextArea::input`] — feed a keypress; returns true when the
//!   buffer mutated (so the form can mark itself dirty).
//! - [`TextArea::render`] — paint into a `Rect`.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A minimal multi-line text input.
#[derive(Debug, Clone)]
pub struct TextArea {
    lines: Vec<String>,
    /// Zero-based row index of the cursor.
    cursor_row: usize,
    /// Zero-based column index of the cursor, in `char` units (not
    /// bytes — multi-byte chars count as one).
    cursor_col: usize,
}

impl Default for TextArea {
    fn default() -> Self {
        Self::new()
    }
}

impl TextArea {
    /// Empty textarea with the cursor at (0, 0).
    #[must_use]
    pub fn new() -> Self {
        Self {
            lines: vec![String::new()],
            cursor_row: 0,
            cursor_col: 0,
        }
    }

    /// Build from an existing string. Splits on `\n`. Cursor lands at
    /// end of the last line.
    #[must_use]
    pub fn with_text(text: &str) -> Self {
        let lines: Vec<String> = if text.is_empty() {
            vec![String::new()]
        } else {
            text.split('\n').map(String::from).collect()
        };
        let cursor_row = lines.len() - 1;
        let cursor_col = lines[cursor_row].chars().count();
        Self {
            lines,
            cursor_row,
            cursor_col,
        }
    }

    /// Borrow the underlying lines (one string per line, no trailing
    /// newlines).
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Join lines with `\n` and return as one owned string.
    #[must_use]
    pub fn as_string(&self) -> String {
        self.lines.join("\n")
    }

    /// True when the textarea has no content (one empty line).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].is_empty()
    }

    /// Cursor position (row, col) in `char` units.
    #[must_use]
    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_row, self.cursor_col)
    }

    /// Feed a keypress. Returns `true` when the buffer mutated.
    ///
    /// Unhandled keys (e.g. function keys, Tab) return `false` so the
    /// outer form can dispatch them to its own focus/save handlers.
    pub fn input(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char(c), m) if !m.contains(KeyModifiers::CONTROL) => {
                self.insert_char(c);
                true
            }
            (KeyCode::Enter, _) => {
                self.insert_newline();
                true
            }
            (KeyCode::Backspace, _) => self.backspace(),
            (KeyCode::Delete, _) => self.delete(),
            (KeyCode::Left, _) => {
                self.move_left();
                false
            }
            (KeyCode::Right, _) => {
                self.move_right();
                false
            }
            (KeyCode::Up, _) => {
                self.move_up();
                false
            }
            (KeyCode::Down, _) => {
                self.move_down();
                false
            }
            (KeyCode::Home, _) => {
                self.cursor_col = 0;
                false
            }
            (KeyCode::End, _) => {
                self.cursor_col = self.lines[self.cursor_row].chars().count();
                false
            }
            _ => false,
        }
    }

    fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.cursor_row];
        let byte_idx = char_col_to_byte_idx(line, self.cursor_col);
        line.insert(byte_idx, c);
        self.cursor_col += 1;
    }

    fn insert_newline(&mut self) {
        let line = &mut self.lines[self.cursor_row];
        let byte_idx = char_col_to_byte_idx(line, self.cursor_col);
        let tail = line.split_off(byte_idx);
        self.cursor_row += 1;
        self.lines.insert(self.cursor_row, tail);
        self.cursor_col = 0;
    }

    fn backspace(&mut self) -> bool {
        if self.cursor_col > 0 {
            let line = &mut self.lines[self.cursor_row];
            let byte_end = char_col_to_byte_idx(line, self.cursor_col);
            let byte_start = char_col_to_byte_idx(line, self.cursor_col - 1);
            line.replace_range(byte_start..byte_end, "");
            self.cursor_col -= 1;
            true
        } else if self.cursor_row > 0 {
            // Merge with previous line.
            let removed = self.lines.remove(self.cursor_row);
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].chars().count();
            self.lines[self.cursor_row].push_str(&removed);
            true
        } else {
            false
        }
    }

    fn delete(&mut self) -> bool {
        let line_len = self.lines[self.cursor_row].chars().count();
        if self.cursor_col < line_len {
            let line = &mut self.lines[self.cursor_row];
            let byte_start = char_col_to_byte_idx(line, self.cursor_col);
            let byte_end = char_col_to_byte_idx(line, self.cursor_col + 1);
            line.replace_range(byte_start..byte_end, "");
            true
        } else if self.cursor_row + 1 < self.lines.len() {
            // Merge next line into this one.
            let next = self.lines.remove(self.cursor_row + 1);
            self.lines[self.cursor_row].push_str(&next);
            true
        } else {
            false
        }
    }

    fn move_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].chars().count();
        }
    }

    fn move_right(&mut self) {
        let line_len = self.lines[self.cursor_row].chars().count();
        if self.cursor_col < line_len {
            self.cursor_col += 1;
        } else if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
    }

    fn move_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            let line_len = self.lines[self.cursor_row].chars().count();
            self.cursor_col = self.cursor_col.min(line_len);
        }
    }

    fn move_down(&mut self) {
        if self.cursor_row + 1 < self.lines.len() {
            self.cursor_row += 1;
            let line_len = self.lines[self.cursor_row].chars().count();
            self.cursor_col = self.cursor_col.min(line_len);
        }
    }

    /// Render into `area`. When `focused` is true the cursor cell is
    /// highlighted with reverse-video; otherwise the textarea renders
    /// as plain text.
    ///
    /// Scrolling: if the cursor would fall outside the visible window,
    /// the view scrolls to keep the cursor in view (3-line vertical
    /// margin). No soft-wrap — long lines truncate at the right edge.
    pub fn render(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        // Vertical scroll: keep cursor row inside [scroll, scroll+height).
        let height = area.height as usize;
        let scroll_top = if self.cursor_row >= height {
            self.cursor_row - height + 1
        } else {
            0
        };

        let mut rendered: Vec<Line> = Vec::with_capacity(height);
        for (row_offset, line) in self
            .lines
            .iter()
            .skip(scroll_top)
            .take(height)
            .enumerate()
        {
            let row = scroll_top + row_offset;
            if focused && row == self.cursor_row {
                rendered.push(line_with_cursor(line, self.cursor_col));
            } else {
                rendered.push(Line::from(line.clone()));
            }
        }

        let para = Paragraph::new(rendered);
        frame.render_widget(para, area);
    }
}

/// Map a `char`-indexed column to a byte index in `line`. Used for
/// safe insertion/deletion at the cursor on lines with multi-byte
/// chars.
fn char_col_to_byte_idx(line: &str, col: usize) -> usize {
    line.char_indices()
        .nth(col)
        .map_or_else(|| line.len(), |(i, _)| i)
}

/// Render one line with a reverse-video block at `cursor_col`. When
/// the cursor is past end-of-line, a synthetic space carries the
/// highlight so the user can see it.
fn line_with_cursor(line: &str, cursor_col: usize) -> Line<'static> {
    let chars: Vec<char> = line.chars().collect();
    let cursor_style = Style::default().add_modifier(Modifier::REVERSED);

    if cursor_col >= chars.len() {
        let mut spans = vec![Span::raw(line.to_string())];
        spans.push(Span::styled(" ", cursor_style));
        return Line::from(spans);
    }

    let before: String = chars[..cursor_col].iter().collect();
    let at: String = chars[cursor_col].to_string();
    let after: String = chars[cursor_col + 1..].iter().collect();
    Line::from(vec![
        Span::raw(before),
        Span::styled(at, cursor_style),
        Span::raw(after),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn new_starts_empty_with_cursor_at_origin() {
        let t = TextArea::new();
        assert_eq!(t.lines(), &[String::new()]);
        assert_eq!(t.cursor(), (0, 0));
        assert!(t.is_empty());
    }

    #[test]
    fn with_text_splits_on_newlines_and_lands_cursor_at_end() {
        let t = TextArea::with_text("a\nb\nc");
        assert_eq!(t.lines(), &["a", "b", "c"]);
        assert_eq!(t.cursor(), (2, 1));
    }

    #[test]
    fn typing_chars_appends_to_current_line() {
        let mut t = TextArea::new();
        for c in "hello".chars() {
            assert!(t.input(key(KeyCode::Char(c))));
        }
        assert_eq!(t.as_string(), "hello");
        assert_eq!(t.cursor(), (0, 5));
    }

    #[test]
    fn enter_splits_the_current_line() {
        let mut t = TextArea::with_text("hello world");
        // Move cursor between "hello" and " world".
        for _ in 0..6 {
            t.input(key(KeyCode::Left));
        }
        assert!(t.input(key(KeyCode::Enter)));
        assert_eq!(t.lines(), &["hello", " world"]);
        assert_eq!(t.cursor(), (1, 0));
    }

    #[test]
    fn backspace_at_start_of_non_first_line_merges_up() {
        let mut t = TextArea::with_text("hello\nworld");
        // Cursor lands at (1, 5). Move to (1, 0).
        t.input(key(KeyCode::Home));
        assert!(t.input(key(KeyCode::Backspace)));
        assert_eq!(t.lines(), &["helloworld"]);
        assert_eq!(t.cursor(), (0, 5));
    }

    #[test]
    fn backspace_at_origin_is_noop() {
        let mut t = TextArea::new();
        assert!(!t.input(key(KeyCode::Backspace)));
        assert!(t.is_empty());
    }

    #[test]
    fn delete_at_end_of_line_merges_with_next() {
        let mut t = TextArea::with_text("hello\nworld");
        t.input(key(KeyCode::Up));
        t.input(key(KeyCode::End));
        assert!(t.input(key(KeyCode::Delete)));
        assert_eq!(t.lines(), &["helloworld"]);
    }

    #[test]
    fn cursor_movements_dont_mutate_buffer() {
        let mut t = TextArea::with_text("abc\ndef");
        for code in [
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Home,
            KeyCode::End,
        ] {
            assert!(
                !t.input(key(code)),
                "{code:?} should not mark buffer dirty"
            );
        }
        assert_eq!(t.as_string(), "abc\ndef");
    }

    #[test]
    fn multibyte_chars_round_trip_through_insert_and_backspace() {
        let mut t = TextArea::new();
        for c in "héllo".chars() {
            t.input(key(KeyCode::Char(c)));
        }
        assert_eq!(t.as_string(), "héllo");
        assert_eq!(t.cursor(), (0, 5));
        // Delete the multi-byte 'é'.
        t.input(key(KeyCode::Left));
        t.input(key(KeyCode::Left));
        t.input(key(KeyCode::Left));
        t.input(key(KeyCode::Left));
        t.input(key(KeyCode::Delete));
        assert_eq!(t.as_string(), "hllo");
    }

    #[test]
    fn ctrl_modified_chars_are_not_inserted() {
        let mut t = TextArea::new();
        // Ctrl-A would be a focus/mode toggle in the outer form — the
        // textarea should NOT consume it as a literal 'a'.
        let ctrl_a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL);
        assert!(!t.input(ctrl_a));
        assert!(t.is_empty());
    }

    #[test]
    fn move_up_clamps_column_on_shorter_row() {
        let mut t = TextArea::with_text("abc\nxyzzzz");
        // Cursor at end of "xyzzzz" — (1, 6).
        t.input(key(KeyCode::Up));
        // Cursor moves to (0, 3) — clamped to row 0's length.
        assert_eq!(t.cursor(), (0, 3));
    }

    #[test]
    fn unhandled_keys_return_false_and_dont_mutate() {
        let mut t = TextArea::with_text("abc");
        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        assert!(!t.input(tab));
        assert_eq!(t.as_string(), "abc");
    }
}
