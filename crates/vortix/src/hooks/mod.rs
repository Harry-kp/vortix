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
#[must_use]
pub fn build_registry_from_config(hooks: &[HookConfig]) -> HookRegistry {
    let mut registry = HookRegistry::new();
    for cfg in hooks {
        match ShellHook::from_config(cfg) {
            Ok(hook) => registry.register(Box::new(hook) as Box<dyn Hook>),
            Err(e) => {
                eprintln!("Warning: skipping hook for event '{}' — {e}", cfg.event);
            }
        }
    }
    registry
}

/// Type-erased registry behind an `Arc` so the journal-subscriber task
/// can hold a clone alongside other consumers.
pub type SharedHookRegistry = Arc<HookRegistry>;
