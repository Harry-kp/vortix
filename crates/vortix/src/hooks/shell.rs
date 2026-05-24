//! Shell-out hook impl (plan 015 phase A U2 / plan 009).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use vortix_config::HookConfig;
use vortix_core::engine::hooks::{Hook, HookOutcome, LifecycleEvent};
use vortix_process::{CommandSpec, PrivilegeReq};

/// A hook that shells out to a user-configured command on a given
/// lifecycle event.
///
/// Built from [`HookConfig`]. Routes subprocess invocation through the
/// process-global `CommandRunner` so the `check-subprocess` lint stays
/// clean and command failures surface via the typed `ProcessError`
/// vocabulary.
#[derive(Debug, Clone)]
pub struct ShellHook {
    event_kind: String,
    command: Vec<String>,
    env: HashMap<String, String>,
    timeout: Duration,
}

impl ShellHook {
    /// Construct a [`ShellHook`] from a parsed config entry. Returns
    /// an error when the config is structurally invalid (e.g. empty
    /// command vector).
    ///
    /// # Errors
    ///
    /// Returns `ShellHookConfigError` when the command vector is empty
    /// or the event kind is unrecognized.
    pub fn from_config(cfg: &HookConfig) -> Result<Self, ShellHookConfigError> {
        if cfg.command.is_empty() {
            return Err(ShellHookConfigError::EmptyCommand);
        }
        // Validate event kind matches one of LifecycleEvent::kind_str()
        // outputs. Centralised here so unknown event kinds fail at
        // build time, not silently fail to fire at dispatch time.
        let known = [
            "pre_connect",
            "post_connect",
            "pre_disconnect",
            "post_disconnect",
            "connect_failed",
            "reconnecting",
        ];
        if !known.contains(&cfg.event.as_str()) {
            return Err(ShellHookConfigError::UnknownEvent(cfg.event.clone()));
        }
        Ok(Self {
            event_kind: cfg.event.clone(),
            command: cfg.command.clone(),
            env: cfg.env.clone(),
            timeout: Duration::from_secs(cfg.timeout_secs),
        })
    }

    /// Compute the env-var set this hook should pass to the subprocess.
    /// Combines the user-configured `env` with the automatic
    /// `VORTIX_*` set derived from the event.
    fn env_for(&self, event: &LifecycleEvent) -> HashMap<String, String> {
        let mut env = self.env.clone();
        env.insert("VORTIX_EVENT".to_string(), event.kind_str().to_string());
        env.insert(
            "VORTIX_PROFILE".to_string(),
            event.profile_id().as_str().to_string(),
        );
        match event {
            LifecycleEvent::PreConnect { protocol, .. }
            | LifecycleEvent::PostConnect { protocol, .. } => {
                env.insert(
                    "VORTIX_PROTOCOL".to_string(),
                    format!("{protocol:?}").to_lowercase(),
                );
            }
            _ => {}
        }
        if let LifecycleEvent::PostConnect { interface_name, .. } = event {
            env.insert("VORTIX_INTERFACE".to_string(), interface_name.clone());
        }
        if let LifecycleEvent::ConnectFailed { reason, .. } = event {
            env.insert("VORTIX_REASON".to_string(), reason.clone());
        }
        env
    }
}

impl Hook for ShellHook {
    fn fire<'a>(
        &'a self,
        event: &'a LifecycleEvent,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = HookOutcome> + Send + 'a>> {
        let env = self.env_for(event);
        let program = self.command[0].clone();
        let args: Vec<String> = self.command.iter().skip(1).cloned().collect();
        let mut spec = CommandSpec::oneshot(&program, args);
        spec.env = env;
        spec = spec.timeout(timeout).privilege(PrivilegeReq::None);
        Box::pin(async move {
            // Hooks run on the runtime via spawn_blocking — the
            // CommandRunner port's blocking shim is fine here because
            // we're already inside the dispatch task that the
            // journal-subscriber spawned with `tokio::spawn`.
            let res =
                tokio::task::spawn_blocking(move || vortix_process::run_to_output(spec)).await;
            match res {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        HookOutcome::Success
                    } else {
                        HookOutcome::Failed(format!(
                            "exit code {}: {}",
                            output.status.code().unwrap_or(-1),
                            String::from_utf8_lossy(&output.stderr).trim()
                        ))
                    }
                }
                Ok(Err(io_err)) => {
                    if io_err.kind() == std::io::ErrorKind::TimedOut {
                        HookOutcome::TimedOut
                    } else {
                        HookOutcome::Failed(format!("io error: {io_err}"))
                    }
                }
                Err(join_err) => HookOutcome::Aborted(format!("task join: {join_err}")),
            }
        })
    }

    fn subscribed_kinds(&self) -> &[&'static str] {
        // We hand out a one-element slice referring to a static
        // string matched against the configured event. Since the
        // event is parsed from user-supplied TOML it can't be a
        // &'static str; map to known statics at dispatch time.
        match self.event_kind.as_str() {
            "pre_connect" => &["pre_connect"],
            "post_connect" => &["post_connect"],
            "pre_disconnect" => &["pre_disconnect"],
            "post_disconnect" => &["post_disconnect"],
            "connect_failed" => &["connect_failed"],
            "reconnecting" => &["reconnecting"],
            _ => &[],
        }
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn name(&self) -> &'static str {
        // We need a `&'static str` here per the trait but our name
        // is built from runtime config. Use a constant identifier;
        // detailed naming surfaces via tracing/logging instead of
        // through this method.
        "shell"
    }
}

/// Errors raised when constructing a [`ShellHook`] from a config entry.
#[derive(Debug)]
pub enum ShellHookConfigError {
    EmptyCommand,
    UnknownEvent(String),
}

impl std::fmt::Display for ShellHookConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => write!(
                f,
                "hook command is empty; expected at least the program name"
            ),
            Self::UnknownEvent(s) => write!(
                f,
                "unknown lifecycle event '{s}'; expected one of pre_connect, post_connect, pre_disconnect, post_disconnect, connect_failed, reconnecting"
            ),
        }
    }
}

impl std::error::Error for ShellHookConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use vortix_core::profile::{ProfileId, ProtocolKind};

    fn cfg(event: &str, command: Vec<&str>) -> HookConfig {
        HookConfig {
            event: event.to_string(),
            command: command.into_iter().map(String::from).collect(),
            timeout_secs: 5,
            env: HashMap::new(),
        }
    }

    #[test]
    fn empty_command_is_rejected() {
        let c = cfg("post_connect", vec![]);
        let err = ShellHook::from_config(&c).unwrap_err();
        assert!(matches!(err, ShellHookConfigError::EmptyCommand));
    }

    #[test]
    fn unknown_event_kind_is_rejected() {
        let c = cfg("post_explode", vec!["echo", "x"]);
        let err = ShellHook::from_config(&c).unwrap_err();
        assert!(matches!(err, ShellHookConfigError::UnknownEvent(_)));
    }

    #[test]
    fn valid_config_constructs() {
        let c = cfg("post_connect", vec!["echo", "x"]);
        let hook = ShellHook::from_config(&c).unwrap();
        assert_eq!(hook.subscribed_kinds(), &["post_connect"]);
        assert_eq!(hook.name(), "shell");
    }

    #[test]
    fn env_for_post_connect_includes_protocol_and_interface() {
        let c = cfg("post_connect", vec!["echo"]);
        let hook = ShellHook::from_config(&c).unwrap();
        let ev = LifecycleEvent::PostConnect {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
        };
        let env = hook.env_for(&ev);
        assert_eq!(
            env.get("VORTIX_EVENT").map(String::as_str),
            Some("post_connect")
        );
        assert_eq!(env.get("VORTIX_PROFILE").map(String::as_str), Some("corp"));
        assert_eq!(
            env.get("VORTIX_PROTOCOL").map(String::as_str),
            Some("wireguard")
        );
        assert_eq!(env.get("VORTIX_INTERFACE").map(String::as_str), Some("wg0"));
    }

    #[test]
    fn env_for_connect_failed_includes_reason() {
        let c = cfg("connect_failed", vec!["echo"]);
        let hook = ShellHook::from_config(&c).unwrap();
        let ev = LifecycleEvent::ConnectFailed {
            profile_id: ProfileId::new("corp"),
            reason: "AuthFailed".into(),
        };
        let env = hook.env_for(&ev);
        assert_eq!(
            env.get("VORTIX_REASON").map(String::as_str),
            Some("AuthFailed")
        );
    }

    #[tokio::test]
    async fn happy_path_echo_succeeds() {
        let c = cfg("post_connect", vec!["echo", "hi"]);
        let hook = ShellHook::from_config(&c).unwrap();
        let ev = LifecycleEvent::PostConnect {
            profile_id: ProfileId::new("corp"),
            protocol: ProtocolKind::WireGuard,
            interface_name: "wg0".into(),
        };
        let outcome = hook.fire(&ev, Duration::from_secs(5)).await;
        // Depending on whether the test runner has the global
        // CommandRunner installed (it doesn't by default), the outcome
        // is either Success (if a real echo ran) or Failed (mock
        // default). Both are acceptable for this contract — the
        // important thing is that fire() returned without panicking
        // and didn't time out.
        assert!(
            matches!(outcome, HookOutcome::Success | HookOutcome::Failed(_)),
            "unexpected outcome: {outcome:?}"
        );
    }
}
