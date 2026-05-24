//! Hook configuration parsed from `settings.toml` (plan 015 phase A / plan 009).
//!
//! Schema (toml):
//!
//! ```toml
//! [[hooks]]
//! event = "post_connect"          # one of pre_connect, post_connect,
//!                                 # pre_disconnect, post_disconnect,
//!                                 # connect_failed, reconnecting
//! command = ["/usr/local/bin/notify-send", "VPN up"]
//! timeout_secs = 5                 # optional, default 5
//!
//! [hooks.env]                      # optional, additional env vars
//! NOTIFY_TITLE = "Vortix"
//! ```
//!
//! Empty by default — zero-overhead when no hooks are configured.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

fn default_timeout_secs() -> u64 {
    5
}

/// One hook entry in `settings.toml`. The presence of any
/// `[[hooks]]` block is opt-in; pre-008 settings files (no field) load
/// with an empty `Vec<HookConfig>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// The lifecycle event kind this hook responds to. Maps to
    /// `vortix_core::engine::hooks::LifecycleEvent::kind_str()`:
    /// `pre_connect`, `post_connect`, `pre_disconnect`,
    /// `post_disconnect`, `connect_failed`, `reconnecting`.
    pub event: String,
    /// Shell argv to invoke. First element is the program, rest are
    /// arguments. Routed through `vortix_process::run_to_output` so
    /// the `check-subprocess` lint stays clean.
    pub command: Vec<String>,
    /// Per-hook timeout. The registry cancels the subprocess when
    /// exceeded.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Extra env vars to set on the hook process, in addition to the
    /// automatic `VORTIX_*` set the registry provides (PROFILE,
    /// PROTOCOL, EVENT, IP).
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Whether the hook is active. `None` means the field was absent
    /// from `settings.toml` (treated as enabled at runtime). `Some(false)`
    /// disables the hook — the entry stays in `Vec<HookConfig>` so the
    /// TUI can render and toggle it, but the registry skips it.
    ///
    /// Plan 017: kept as `Option` (not `bool` with `#[serde(default)]`)
    /// so the writer can omit the line for entries that never had it,
    /// preserving hand-edited settings.toml round-trip exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl HookConfig {
    /// True when the hook should be registered. Maps `None` → true so
    /// pre-plan-017 settings files behave as before.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// Mutable view of the `[[hooks]]` array used by the TUI's hook
/// management surface (plan 017 U3). A thin newtype over
/// `Vec<HookConfig>` so the four CRUD ops carry a shared invariant
/// home and aren't sprinkled across the binary crate as free
/// functions on `Vec`.
#[derive(Debug, Clone, Default)]
pub struct HooksList(Vec<HookConfig>);

impl HooksList {
    /// Build from an existing `Vec<HookConfig>` (typically
    /// `Settings::load().hooks`).
    #[must_use]
    pub fn new(hooks: Vec<HookConfig>) -> Self {
        Self(hooks)
    }

    /// Borrow the underlying slice for read-only access (UI rendering,
    /// passing to the writer).
    #[must_use]
    pub fn as_slice(&self) -> &[HookConfig] {
        &self.0
    }

    /// Total entry count (including disabled).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow one entry by index.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&HookConfig> {
        self.0.get(idx)
    }

    /// Append a new entry.
    pub fn add(&mut self, cfg: HookConfig) {
        self.0.push(cfg);
    }

    /// Replace the entry at `idx`. Returns the old entry on success,
    /// `None` when `idx` is out of bounds (list unchanged).
    pub fn replace(&mut self, idx: usize, cfg: HookConfig) -> Option<HookConfig> {
        if idx >= self.0.len() {
            return None;
        }
        Some(std::mem::replace(&mut self.0[idx], cfg))
    }

    /// Remove and return the entry at `idx`. `None` when out of
    /// bounds (list unchanged).
    pub fn remove(&mut self, idx: usize) -> Option<HookConfig> {
        if idx >= self.0.len() {
            return None;
        }
        Some(self.0.remove(idx))
    }

    /// Flip the `enabled` field for the entry at `idx`. `None`
    /// (absent) → `Some(false)`; `Some(true)` → `Some(false)`;
    /// `Some(false)` → `Some(true)`. Returns the new effective state
    /// (`is_enabled()` after toggle) or `false` when out of bounds.
    pub fn toggle(&mut self, idx: usize) -> bool {
        let Some(entry) = self.0.get_mut(idx) else {
            return false;
        };
        let new_state = !entry.is_enabled();
        entry.enabled = Some(new_state);
        new_state
    }

    /// Consume into the inner `Vec` (for the writer's slice).
    #[must_use]
    pub fn into_inner(self) -> Vec<HookConfig> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_hook_parses_with_defaults() {
        let toml_str = r#"
            event = "post_connect"
            command = ["echo", "hi"]
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.event, "post_connect");
        assert_eq!(cfg.command, vec!["echo".to_string(), "hi".to_string()]);
        assert_eq!(cfg.timeout_secs, 5);
        assert!(cfg.env.is_empty());
    }

    #[test]
    fn full_hook_parses_with_env_and_timeout() {
        let toml_str = r#"
            event = "pre_connect"
            command = ["/usr/local/bin/notify-send", "Vortix"]
            timeout_secs = 30
            [env]
            NOTIFY_TITLE = "Vortix"
            ICON = "shield"
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.event, "pre_connect");
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.env.len(), 2);
        assert_eq!(cfg.env.get("NOTIFY_TITLE"), Some(&"Vortix".to_string()));
    }

    #[test]
    fn empty_command_still_parses_but_is_caller_responsibility() {
        // Schema doesn't forbid empty command; ShellHook fails fast on
        // dispatch if it's empty. Keep deserialization permissive.
        let toml_str = r#"
            event = "post_connect"
            command = []
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.command.is_empty());
    }

    #[derive(Deserialize)]
    struct Wrapper {
        hooks: Vec<HookConfig>,
    }

    // Plan 017 U3 — HooksList mutation API.

    fn cfg(event: &str, enabled: Option<bool>) -> HookConfig {
        HookConfig {
            event: event.into(),
            command: vec!["true".into()],
            timeout_secs: 5,
            env: HashMap::new(),
            enabled,
        }
    }

    #[test]
    fn add_appends_a_new_entry() {
        let mut list = HooksList::default();
        list.add(cfg("post_connect", None));
        assert_eq!(list.len(), 1);
        list.add(cfg("post_disconnect", None));
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).unwrap().event, "post_connect");
        assert_eq!(list.get(1).unwrap().event, "post_disconnect");
    }

    #[test]
    fn replace_at_valid_index_returns_old_entry() {
        let mut list = HooksList::new(vec![
            cfg("post_connect", None),
            cfg("post_disconnect", None),
        ]);
        let old = list.replace(0, cfg("connect_failed", Some(false))).unwrap();
        assert_eq!(old.event, "post_connect");
        assert_eq!(list.get(0).unwrap().event, "connect_failed");
        assert_eq!(list.get(0).unwrap().enabled, Some(false));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn replace_out_of_bounds_returns_none_no_change() {
        let mut list = HooksList::new(vec![cfg("post_connect", None)]);
        let result = list.replace(99, cfg("connect_failed", None));
        assert!(result.is_none());
        assert_eq!(list.len(), 1);
        assert_eq!(list.get(0).unwrap().event, "post_connect");
    }

    #[test]
    fn remove_at_valid_index_shrinks_list() {
        let mut list = HooksList::new(vec![
            cfg("a", None),
            cfg("b", None),
            cfg("c", None),
        ]);
        let removed = list.remove(1).unwrap();
        assert_eq!(removed.event, "b");
        assert_eq!(list.len(), 2);
        assert_eq!(list.get(0).unwrap().event, "a");
        assert_eq!(list.get(1).unwrap().event, "c");
    }

    #[test]
    fn remove_out_of_bounds_returns_none_no_change() {
        let mut list = HooksList::new(vec![cfg("a", None)]);
        let result = list.remove(99);
        assert!(result.is_none());
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn toggle_from_none_becomes_some_false_and_returns_false() {
        let mut list = HooksList::new(vec![cfg("a", None)]);
        let new_state = list.toggle(0);
        assert!(!new_state);
        assert_eq!(list.get(0).unwrap().enabled, Some(false));
    }

    #[test]
    fn toggle_from_some_true_becomes_some_false() {
        let mut list = HooksList::new(vec![cfg("a", Some(true))]);
        assert!(!list.toggle(0));
        assert_eq!(list.get(0).unwrap().enabled, Some(false));
    }

    #[test]
    fn toggle_from_some_false_becomes_some_true_and_returns_true() {
        let mut list = HooksList::new(vec![cfg("a", Some(false))]);
        assert!(list.toggle(0));
        assert_eq!(list.get(0).unwrap().enabled, Some(true));
    }

    #[test]
    fn toggle_out_of_bounds_is_a_noop_returns_false() {
        let mut list = HooksList::new(vec![cfg("a", Some(true))]);
        assert!(!list.toggle(99));
        assert_eq!(list.get(0).unwrap().enabled, Some(true));
    }

    // Plan 017 U1 — enabled field semantics.

    #[test]
    fn enabled_absent_in_toml_parses_as_none_and_is_enabled() {
        let toml_str = r#"
            event = "post_connect"
            command = ["echo", "hi"]
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert!(cfg.enabled.is_none());
        assert!(cfg.is_enabled());
    }

    #[test]
    fn enabled_true_parses_and_is_enabled() {
        let toml_str = r#"
            event = "post_connect"
            command = ["echo", "hi"]
            enabled = true
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.enabled, Some(true));
        assert!(cfg.is_enabled());
    }

    #[test]
    fn enabled_false_parses_and_skips_at_runtime() {
        let toml_str = r#"
            event = "post_connect"
            command = ["echo", "hi"]
            enabled = false
        "#;
        let cfg: HookConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.enabled, Some(false));
        assert!(!cfg.is_enabled());
    }

    #[test]
    fn enabled_none_does_not_serialize() {
        let cfg = HookConfig {
            event: "post_connect".into(),
            command: vec!["echo".into(), "hi".into()],
            timeout_secs: 5,
            env: HashMap::new(),
            enabled: None,
        };
        let out = toml::to_string(&cfg).unwrap();
        assert!(!out.contains("enabled"), "serialized output: {out}");
    }

    #[test]
    fn enabled_some_false_serializes_explicitly() {
        let cfg = HookConfig {
            event: "post_connect".into(),
            command: vec!["echo".into(), "hi".into()],
            timeout_secs: 5,
            env: HashMap::new(),
            enabled: Some(false),
        };
        let out = toml::to_string(&cfg).unwrap();
        assert!(out.contains("enabled = false"), "serialized output: {out}");
    }

    #[test]
    fn hook_array_in_settings_round_trips() {
        let toml_str = r#"
            [[hooks]]
            event = "post_connect"
            command = ["echo", "up"]

            [[hooks]]
            event = "post_disconnect"
            command = ["echo", "down"]
            timeout_secs = 10
        "#;
        let w: Wrapper = toml::from_str(toml_str).unwrap();
        assert_eq!(w.hooks.len(), 2);
        assert_eq!(w.hooks[0].event, "post_connect");
        assert_eq!(w.hooks[1].timeout_secs, 10);
    }
}
