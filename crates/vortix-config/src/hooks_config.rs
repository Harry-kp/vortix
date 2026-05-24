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
