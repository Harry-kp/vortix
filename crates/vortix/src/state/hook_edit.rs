// Allow pedantic doc-markdown noise — the doc comments in this file
// reference type names and field paths that the lint wants in
// backticks. Rather than spray ten thousand backticks, allow the
// lint for the module.
#![allow(clippy::doc_markdown)]

//! Hook editor form state (plan 017 U5).
//!
//! Stored inside `InputMode::HookEdit` so the form survives across
//! input loop iterations without re-deriving from disk. The form
//! holds raw string buffers (not parsed types) so the user sees what
//! they typed mid-edit — parsing/validation happens at save time.

use std::time::SystemTime;
use vortix_config::HookConfig;

use crate::ui::widgets::textarea::TextArea;

/// What the form is targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEditTarget {
    /// Add a brand-new hook.
    AddingNew,
    /// Edit the hook at the given index in `App.registered_hooks`.
    EditingExisting { index: usize },
}

/// Which form field has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEditField {
    /// Event-kind picker (single-select).
    Event,
    /// Name single-line input.
    Name,
    /// Command multi-line textarea.
    Command,
    /// Timeout numeric input.
    Timeout,
    /// One of the env rows (with the column inside).
    EnvKey(usize),
    EnvValue(usize),
    /// "+ Add env var" pseudo-button.
    EnvAdd,
    /// Enabled checkbox.
    Enabled,
    /// Save button.
    Save,
    /// Cancel button.
    Cancel,
}

/// The 6 valid lifecycle events. Mirrors
/// `vortix_core::engine::hooks::LifecycleEvent::kind_str()` so the
/// picker can't produce a value the FSM doesn't emit.
pub const EVENT_KINDS: [&str; 6] = [
    "pre_connect",
    "post_connect",
    "pre_disconnect",
    "post_disconnect",
    "connect_failed",
    "reconnecting",
];

/// Hook editor form state.
///
/// Boxed inside `InputMode::HookEdit` so the InputMode enum stays
/// reasonably sized — TextArea + several String + Vec fields would
/// otherwise inflate every InputMode case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEditState {
    pub target: HookEditTarget,
    /// `settings.toml` mtime at form-open time. Used by the U8 save
    /// pipeline to detect external edits. `None` when the file
    /// doesn't exist yet (first hook on a fresh install).
    pub original_mtime: Option<SystemTime>,

    // ---- Field values ----
    /// Index into `EVENT_KINDS`.
    pub event_idx: usize,
    pub name: String,
    pub name_cursor: usize,
    /// Multi-line shell command. Saved as `["sh", "-c", as_string()]`.
    pub command: TextArea,
    /// Numeric input; parsed at save time. Empty string means "use
    /// schema default of 5".
    pub timeout_input: String,
    pub timeout_cursor: usize,
    pub env: Vec<EnvRow>,
    pub enabled: bool,

    // ---- UI state ----
    pub focused: HookEditField,
    pub dirty: bool,
    /// Inline validation error from the last save attempt; cleared on
    /// next mutation.
    pub validation_error: Option<String>,
}

/// One env-var row (key+value with their cursors).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvRow {
    pub key: String,
    pub key_cursor: usize,
    pub value: String,
    pub value_cursor: usize,
}

impl HookEditState {
    /// Fresh form for adding a new hook. Defaults: event=post_connect,
    /// enabled=true, timeout=blank (uses schema default), no env rows.
    #[must_use]
    pub fn new_add(original_mtime: Option<SystemTime>) -> Self {
        Self {
            target: HookEditTarget::AddingNew,
            original_mtime,
            event_idx: 1, // post_connect — most common case
            name: String::new(),
            name_cursor: 0,
            command: TextArea::new(),
            timeout_input: String::new(),
            timeout_cursor: 0,
            env: Vec::new(),
            enabled: true,
            focused: HookEditField::Event,
            dirty: false,
            validation_error: None,
        }
    }

    /// Form pre-filled from an existing hook.
    ///
    /// Command-field mapping: a hook of shape `["sh"|"bash", "-c", X]`
    /// loads X into the textarea verbatim. Literal-argv hooks get
    /// `shlex::join`'d into a single shell-string representation —
    /// editing them through the TUI does rewrap on save as
    /// `["sh", "-c", ...]`, which is documented behaviour for v0.3.0.
    /// Pure-argv editing earns its own UI in a later iteration.
    #[must_use]
    pub fn new_edit(
        index: usize,
        cfg: &HookConfig,
        original_mtime: Option<SystemTime>,
    ) -> Self {
        let event_idx = EVENT_KINDS
            .iter()
            .position(|k| *k == cfg.event)
            .unwrap_or(1);
        let command_text = command_to_shell_text(&cfg.command);
        let timeout_input = if cfg.timeout_secs == 5 {
            String::new()
        } else {
            cfg.timeout_secs.to_string()
        };
        let env: Vec<EnvRow> = {
            let mut rows: Vec<(&String, &String)> = cfg.env.iter().collect();
            rows.sort_by_key(|(k, _)| (*k).clone());
            rows.into_iter()
                .map(|(k, v)| EnvRow {
                    key: k.clone(),
                    key_cursor: k.chars().count(),
                    value: v.clone(),
                    value_cursor: v.chars().count(),
                })
                .collect()
        };
        Self {
            target: HookEditTarget::EditingExisting { index },
            original_mtime,
            event_idx,
            name: derive_name_from_cfg(cfg),
            name_cursor: derive_name_from_cfg(cfg).chars().count(),
            command: TextArea::with_text(&command_text),
            timeout_cursor: timeout_input.chars().count(),
            timeout_input,
            env,
            enabled: cfg.is_enabled(),
            focused: HookEditField::Event,
            dirty: false,
            validation_error: None,
        }
    }

    /// True when the user has typed anything since the form opened.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Selected event kind as the canonical lowercase string.
    #[must_use]
    pub fn event_kind(&self) -> &'static str {
        EVENT_KINDS[self.event_idx]
    }

    /// Build a [`HookConfig`] from the current form values. Returns
    /// `Err(msg)` when validation fails. Side effect: stores the
    /// error on `self.validation_error` and focuses the offending
    /// field so the next render highlights it.
    ///
    /// # Errors
    /// Returns the user-facing validation message for the first
    /// failing field; the form is unchanged on disk.
    pub fn to_config(&mut self) -> Result<HookConfig, String> {
        // Name — required, single line, no leading/trailing whitespace.
        let name_trimmed = self.name.trim();
        if name_trimmed.is_empty() {
            return self.fail(HookEditField::Name, "Name is required");
        }

        // Command — required.
        if self.command.is_empty() {
            return self.fail(HookEditField::Command, "Command is required");
        }
        let cmd_string = self.command.as_string();
        if cmd_string.trim().is_empty() {
            return self.fail(HookEditField::Command, "Command is required");
        }

        // Timeout — empty → default 5; otherwise parse as u64 > 0.
        let timeout_secs = if self.timeout_input.trim().is_empty() {
            5
        } else {
            match self.timeout_input.trim().parse::<u64>() {
                Ok(n) if n > 0 => n,
                _ => {
                    return self.fail(
                        HookEditField::Timeout,
                        "Timeout must be a positive integer (seconds)",
                    );
                }
            }
        };

        // Env — every row must have a non-empty key; values may be
        // empty (some hooks set env-presence flags).
        let mut env_map = std::collections::HashMap::new();
        for (i, row) in self.env.iter().enumerate() {
            let key = row.key.trim();
            if key.is_empty() && !row.value.trim().is_empty() {
                return self.fail(
                    HookEditField::EnvKey(i),
                    "Env key is required when value is set",
                );
            }
            if !key.is_empty() {
                env_map.insert(key.to_string(), row.value.clone());
            }
        }

        // Name lives at the front of the command as a comment so the
        // journal/overlay can render a human-readable label. We don't
        // have a "name" field in HookConfig (settings.toml schema is
        // event/command/timeout/env/enabled), so the name we collect
        // here is purely informational and ends up encoded into the
        // [[hooks]] entry via a synthetic env var VORTIX_HOOK_NAME.
        // (Future schema evolution may add a first-class name field.)
        if !env_map.contains_key("VORTIX_HOOK_NAME") {
            env_map.insert("VORTIX_HOOK_NAME".into(), name_trimmed.into());
        }

        self.validation_error = None;
        Ok(HookConfig {
            event: self.event_kind().to_string(),
            command: vec![
                "sh".into(),
                "-c".into(),
                cmd_string,
            ],
            timeout_secs,
            env: env_map,
            enabled: if self.enabled { None } else { Some(false) },
        })
    }

    fn fail(&mut self, focus: HookEditField, msg: &str) -> Result<HookConfig, String> {
        self.focused = focus;
        self.validation_error = Some(msg.to_string());
        Err(msg.to_string())
    }
}

/// Decode the hook's argv into the shell-string the textarea
/// displays. The two recognized shapes:
/// - `["sh"|"bash", "-c", X]` → `X` verbatim.
/// - everything else → `shlex::join`'d single line so the user can
///   edit it; saving will rewrap as `["sh", "-c", ...]`.
fn command_to_shell_text(argv: &[String]) -> String {
    if argv.len() == 3 && (argv[0] == "sh" || argv[0] == "bash") && argv[1] == "-c" {
        return argv[2].clone();
    }
    // Fallback: join with simple quoting. We don't depend on `shlex`
    // here — the v0.3.0 form always re-saves as sh -c X, so
    // round-tripping pure argv through the TUI is documented as
    // lossy. Use a minimal quote-where-needed join.
    argv.iter()
        .map(|s| shell_quote(s))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quote `s` for inclusion in a shell-string when it contains
/// characters that would be split by sh word-splitting. Single-quote
/// strategy: wrap in `'…'`, escaping embedded single quotes as
/// `'\''`. Correct for any input (including newlines).
fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "/_-.".contains(c)) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Best-effort human-readable name for an existing config.
///
/// Priority: explicit `VORTIX_HOOK_NAME` env var (set by the TUI on
/// every TUI-authored hook), otherwise `event:program-basename`.
fn derive_name_from_cfg(cfg: &HookConfig) -> String {
    if let Some(n) = cfg.env.get("VORTIX_HOOK_NAME") {
        return n.clone();
    }
    let program_basename = cfg
        .command
        .first()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("hook")
        .to_string();
    format!("{}:{program_basename}", cfg.event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn hook(event: &str, argv: &[&str]) -> HookConfig {
        HookConfig {
            event: event.into(),
            command: argv.iter().map(|s| (*s).to_string()).collect(),
            timeout_secs: 5,
            env: HashMap::new(),
            enabled: None,
        }
    }

    #[test]
    fn new_add_starts_with_defaults_clean() {
        let s = HookEditState::new_add(None);
        assert_eq!(s.target, HookEditTarget::AddingNew);
        assert_eq!(s.event_kind(), "post_connect");
        assert_eq!(s.name, "");
        assert!(s.command.is_empty());
        assert_eq!(s.timeout_input, "");
        assert!(s.env.is_empty());
        assert!(s.enabled);
        assert!(!s.is_dirty());
    }

    #[test]
    fn new_edit_loads_sh_dash_c_command_verbatim() {
        let h = hook("post_connect", &["sh", "-c", "echo hi\ndate"]);
        let s = HookEditState::new_edit(3, &h, None);
        assert_eq!(s.target, HookEditTarget::EditingExisting { index: 3 });
        assert_eq!(s.command.as_string(), "echo hi\ndate");
    }

    #[test]
    fn new_edit_falls_back_to_shell_quoted_argv_join_for_literal_commands() {
        let h = hook("post_connect", &["notify-send", "VPN up", "with spaces"]);
        let s = HookEditState::new_edit(0, &h, None);
        // Bare alphanumerics unquoted; spaced args wrapped in single
        // quotes.
        assert_eq!(s.command.as_string(), "notify-send 'VPN up' 'with spaces'");
    }

    #[test]
    fn new_edit_picks_up_existing_event_kind() {
        let h = hook("connect_failed", &["sh", "-c", "true"]);
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.event_kind(), "connect_failed");
    }

    #[test]
    fn new_edit_unknown_event_kind_falls_back_to_post_connect() {
        let h = hook("bogus_event", &["sh", "-c", "true"]);
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.event_kind(), "post_connect");
    }

    #[test]
    fn new_edit_loads_name_from_vortix_hook_name_env() {
        let mut h = hook("post_connect", &["sh", "-c", "true"]);
        h.env.insert("VORTIX_HOOK_NAME".into(), "slack-notify".into());
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.name, "slack-notify");
    }

    #[test]
    fn new_edit_derives_name_from_argv_when_env_missing() {
        let h = hook("post_connect", &["/usr/local/bin/notify-send", "hi"]);
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.name, "post_connect:notify-send");
    }

    #[test]
    fn new_edit_timeout_default_loads_as_empty_string() {
        let h = hook("post_connect", &["sh", "-c", "true"]);
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.timeout_input, "");
    }

    #[test]
    fn new_edit_non_default_timeout_loads_as_string() {
        let mut h = hook("post_connect", &["sh", "-c", "true"]);
        h.timeout_secs = 30;
        let s = HookEditState::new_edit(0, &h, None);
        assert_eq!(s.timeout_input, "30");
    }

    #[test]
    fn new_edit_enabled_false_carries_through() {
        let mut h = hook("post_connect", &["sh", "-c", "true"]);
        h.enabled = Some(false);
        let s = HookEditState::new_edit(0, &h, None);
        assert!(!s.enabled);
    }

    #[test]
    fn to_config_rejects_empty_name() {
        let mut s = HookEditState::new_add(None);
        s.command = TextArea::with_text("echo hi");
        let err = s.to_config().expect_err("empty name should fail");
        assert!(err.to_lowercase().contains("name"));
        assert_eq!(s.focused, HookEditField::Name);
    }

    #[test]
    fn to_config_rejects_empty_command() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        let err = s.to_config().expect_err("empty command should fail");
        assert!(err.to_lowercase().contains("command"));
        assert_eq!(s.focused, HookEditField::Command);
    }

    #[test]
    fn to_config_rejects_whitespace_only_command() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("   \n  \t");
        let err = s.to_config().expect_err("whitespace-only command should fail");
        assert!(err.to_lowercase().contains("command"));
    }

    #[test]
    fn to_config_rejects_non_numeric_timeout() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.timeout_input = "abc".into();
        let err = s.to_config().expect_err("non-numeric timeout should fail");
        assert!(err.to_lowercase().contains("timeout"));
        assert_eq!(s.focused, HookEditField::Timeout);
    }

    #[test]
    fn to_config_rejects_zero_timeout() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.timeout_input = "0".into();
        assert!(s.to_config().is_err());
    }

    #[test]
    fn to_config_empty_timeout_uses_default_5() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        let cfg = s.to_config().expect("valid");
        assert_eq!(cfg.timeout_secs, 5);
    }

    #[test]
    fn to_config_wraps_command_as_sh_dash_c() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("notify-send 'hi there'");
        let cfg = s.to_config().expect("valid");
        assert_eq!(cfg.command, vec!["sh", "-c", "notify-send 'hi there'"]);
    }

    #[test]
    fn to_config_preserves_multi_line_command() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo hi\ndate\nuptime");
        let cfg = s.to_config().expect("valid");
        assert_eq!(cfg.command[2], "echo hi\ndate\nuptime");
    }

    #[test]
    fn to_config_serializes_disabled_as_some_false() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.enabled = false;
        let cfg = s.to_config().expect("valid");
        assert_eq!(cfg.enabled, Some(false));
    }

    #[test]
    fn to_config_serializes_enabled_as_none() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.enabled = true;
        let cfg = s.to_config().expect("valid");
        assert!(cfg.enabled.is_none());
    }

    #[test]
    fn to_config_emits_vortix_hook_name_env_var() {
        let mut s = HookEditState::new_add(None);
        s.name = "slack-notify".into();
        s.command = TextArea::with_text("echo");
        let cfg = s.to_config().expect("valid");
        assert_eq!(
            cfg.env.get("VORTIX_HOOK_NAME"),
            Some(&"slack-notify".to_string())
        );
    }

    #[test]
    fn to_config_rejects_env_row_with_value_but_no_key() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.env.push(EnvRow {
            key: String::new(),
            value: "lonely".into(),
            ..Default::default()
        });
        let err = s.to_config().expect_err("value-without-key should fail");
        assert!(err.to_lowercase().contains("key"));
        assert_eq!(s.focused, HookEditField::EnvKey(0));
    }

    #[test]
    fn to_config_drops_env_rows_fully_blank() {
        let mut s = HookEditState::new_add(None);
        s.name = "x".into();
        s.command = TextArea::with_text("echo");
        s.env.push(EnvRow::default());
        s.env.push(EnvRow {
            key: "REAL".into(),
            value: "1".into(),
            ..Default::default()
        });
        let cfg = s.to_config().expect("valid");
        // Real row + auto VORTIX_HOOK_NAME = 2.
        assert_eq!(cfg.env.len(), 2);
        assert_eq!(cfg.env.get("REAL"), Some(&"1".to_string()));
    }
}
