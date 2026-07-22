//! Validated global lifecycle-hook configuration.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::control::hooks::HookEvent;

pub const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 5;
pub const MAX_HOOK_TIMEOUT_SECS: u64 = 60;
pub const MAX_HOOK_SPECS: usize = 64;
pub const MAX_HOOK_ARGS: usize = 64;
pub const MAX_HOOK_ARG_BYTES: usize = 4 * 1024;
pub const MAX_HOOK_ARGV_BYTES: usize = 16 * 1024;

fn default_timeout_secs() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECS
}

/// One immutable global observer hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSpec {
    pub event: HookEvent,
    pub executable: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

impl HookSpec {
    pub fn validate(&self) -> Result<(), HookConfigError> {
        if !self.executable.is_absolute() {
            return Err(HookConfigError::ExecutableNotAbsolute {
                executable: self.executable.clone(),
            });
        }
        let executable = self
            .executable
            .to_str()
            .ok_or(HookConfigError::ExecutableNotUtf8)?;
        if executable.is_empty()
            || executable.len() > MAX_HOOK_ARG_BYTES
            || executable.as_bytes().contains(&0)
        {
            return Err(HookConfigError::ExecutableTooLong);
        }
        if self.args.len() > MAX_HOOK_ARGS {
            return Err(HookConfigError::TooManyArguments {
                found: self.args.len(),
            });
        }
        let mut total = executable.len();
        for argument in &self.args {
            if argument.len() > MAX_HOOK_ARG_BYTES || argument.as_bytes().contains(&0) {
                return Err(HookConfigError::InvalidArgument);
            }
            total = total.saturating_add(argument.len());
        }
        if total > MAX_HOOK_ARGV_BYTES {
            return Err(HookConfigError::ArgumentsTooLarge);
        }
        if !(1..=MAX_HOOK_TIMEOUT_SECS).contains(&self.timeout_secs) {
            return Err(HookConfigError::InvalidTimeout {
                found: self.timeout_secs,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

pub fn validate_hooks(hooks: &[HookSpec]) -> Result<(), HookConfigError> {
    if hooks.len() > MAX_HOOK_SPECS {
        return Err(HookConfigError::TooManyHooks { found: hooks.len() });
    }
    hooks.iter().try_for_each(HookSpec::validate)
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookConfigError {
    #[error("hook executable must be an absolute path: {executable}")]
    ExecutableNotAbsolute { executable: PathBuf },
    #[error("hook executable path is empty, contains NUL, or exceeds 4096 bytes")]
    ExecutableTooLong,
    #[error("hook executable path must be valid UTF-8")]
    ExecutableNotUtf8,
    #[error("hook has {found} arguments; maximum is {MAX_HOOK_ARGS}")]
    TooManyArguments { found: usize },
    #[error("hook argument is invalid or exceeds {MAX_HOOK_ARG_BYTES} bytes")]
    InvalidArgument,
    #[error("hook executable and argv exceed {MAX_HOOK_ARGV_BYTES} bytes")]
    ArgumentsTooLarge,
    #[error("hook timeout {found}s is outside 1..={MAX_HOOK_TIMEOUT_SECS}s")]
    InvalidTimeout { found: u64 },
    #[error("settings contain {found} hooks; maximum is {MAX_HOOK_SPECS}")]
    TooManyHooks { found: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> HookSpec {
        HookSpec {
            event: HookEvent::Connected,
            executable: PathBuf::from("/usr/bin/notify-send"),
            args: vec!["VPN connected".into()],
            timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
        }
    }

    #[test]
    fn validates_absolute_argv_hook() {
        spec().validate().unwrap();
    }

    #[test]
    fn rejects_shell_text_in_executable_position() {
        let mut hook = spec();
        hook.executable = PathBuf::from("notify-send VPN-connected");
        assert!(matches!(
            hook.validate(),
            Err(HookConfigError::ExecutableNotAbsolute { .. })
        ));
    }

    #[test]
    fn rejects_nul_before_process_admission() {
        let mut hook = spec();
        hook.executable = PathBuf::from("/usr/bin/true\0ignored");
        assert!(matches!(
            hook.validate(),
            Err(HookConfigError::ExecutableTooLong)
        ));
        hook.executable = PathBuf::from("/usr/bin/true");
        hook.args = vec!["safe\0ignored".into()];
        assert!(matches!(
            hook.validate(),
            Err(HookConfigError::InvalidArgument)
        ));
    }

    #[test]
    fn rejects_zero_and_excessive_timeouts() {
        let mut hook = spec();
        hook.timeout_secs = 0;
        assert!(matches!(
            hook.validate(),
            Err(HookConfigError::InvalidTimeout { .. })
        ));
        hook.timeout_secs = MAX_HOOK_TIMEOUT_SECS + 1;
        assert!(matches!(
            hook.validate(),
            Err(HookConfigError::InvalidTimeout { .. })
        ));
    }
}
