//! Lifecycle hook impls (plan 015 phase A / plan 009).
//!
//! `ShellHook` is the only concrete impl shipped in v0.3.0. It shells
//! out via the `CommandRunner` port (so `check-subprocess` stays clean)
//! and respects per-hook timeout + env var configuration parsed from
//! `settings.toml`.

mod shell;

pub use shell::ShellHook;

use std::sync::Arc;

use vortix_config::HookConfig;
use vortix_core::engine::hooks::{Hook, HookRegistry};

/// Build a [`HookRegistry`] from the user's `settings.toml` `[[hooks]]`
/// entries. Returns an empty registry when no hooks are configured —
/// the journal-subscriber task can skip spawning entirely in that case.
///
/// `eprintln!` is reserved for headless/CLI flows. The TUI variant
/// [`build_registry_from_config_collecting`] returns the errors so the
/// caller can surface them via toast + overlay (plan 016 U5).
#[must_use]
pub fn build_registry_from_config(hooks: &[HookConfig]) -> HookRegistry {
    let (registry, errors) = build_registry_from_config_collecting(hooks);
    for e in &errors {
        eprintln!("{e}");
    }
    registry
}

/// Same as [`build_registry_from_config`] but returns malformed-entry
/// errors instead of writing them to stderr. Used by the TUI startup
/// path so users see config errors as a toast (plan 016 U5) rather
/// than swallowed into a log file they may not read.
#[must_use]
pub fn build_registry_from_config_collecting(
    hooks: &[HookConfig],
) -> (HookRegistry, Vec<String>) {
    let mut registry = HookRegistry::new();
    let mut errors = Vec::new();
    for cfg in hooks {
        // Plan 017 U1: skip disabled entries — they stay in the
        // settings.toml model (so the TUI can render and toggle them)
        // but never reach the running registry.
        if !cfg.is_enabled() {
            continue;
        }
        match ShellHook::from_config(cfg) {
            Ok(hook) => registry.register(Box::new(hook) as Box<dyn Hook>),
            Err(e) => {
                errors.push(format!(
                    "Warning: skipping hook for event '{}' — {e}",
                    cfg.event
                ));
            }
        }
    }
    (registry, errors)
}

/// Type-erased registry behind an `Arc` so the journal-subscriber task
/// can hold a clone alongside other consumers.
pub type SharedHookRegistry = Arc<HookRegistry>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
    fn registry_skips_disabled_entries_but_keeps_enabled() {
        let hooks = vec![
            cfg("post_connect", None),         // enabled (default)
            cfg("post_disconnect", Some(false)), // disabled — skipped
            cfg("connect_failed", Some(true)), // enabled
        ];
        let (registry, errors) = build_registry_from_config_collecting(&hooks);
        assert!(errors.is_empty(), "errors: {errors:?}");
        assert_eq!(
            registry.len(),
            2,
            "disabled entry should not reach the registry"
        );
    }

    #[test]
    fn registry_built_from_all_disabled_is_empty_no_errors() {
        let hooks = vec![cfg("post_connect", Some(false))];
        let (registry, errors) = build_registry_from_config_collecting(&hooks);
        assert!(errors.is_empty());
        assert_eq!(registry.len(), 0);
    }
}
