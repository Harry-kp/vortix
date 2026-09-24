//! `Settings` struct + figment-layered resolution.
//!
//! Layer precedence (last wins): defaults → `<config_dir>/settings.toml` →
//! `VORTIX_*` env vars.

use std::path::{Path, PathBuf};
use std::time::Duration;

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hooks::HookEvent;

/// Current schema version for `settings.toml`.
///
/// Bump when a settings field renames, removes, or changes type.
/// Additive field additions do not require a bump.
pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    SETTINGS_SCHEMA_VERSION
}

/// Top-level settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Schema version of the user's `settings.toml`. Files without the field
    /// read as 1; a newer version than this build knows is refused.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub engine: EngineSettings,
    pub journal: JournalSettings,
    /// Global, asynchronous lifecycle observers. Empty means no runner task.
    pub hooks: Vec<HookSpec>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            engine: EngineSettings::default(),
            journal: JournalSettings::default(),
            hooks: Vec::new(),
        }
    }
}

/// Protocol and handshake knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineSettings {
    /// Default `OpenVPN --verb` value.
    pub openvpn_verbosity: String,
    /// `OpenVPN` connect timeout.
    pub connect_timeout_secs: u64,
    /// `WireGuard` remains Handshaking until current-generation evidence arrives.
    pub wireguard_handshake_timeout_secs: u64,
    /// Ongoing freshness threshold when peer traffic is expected.
    pub wireguard_handshake_stale_secs: u64,
    /// Ordered explicit probe destinations used to elicit a handshake.
    pub wireguard_health_targets: Vec<String>,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            openvpn_verbosity: "3".to_string(),
            connect_timeout_secs: crate::constants::DEFAULT_CONNECT_TIMEOUT,
            wireguard_handshake_timeout_secs: crate::constants::DEFAULT_WIREGUARD_HANDSHAKE_TIMEOUT,
            wireguard_handshake_stale_secs: 180,
            wireguard_health_targets: vec![
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
                "9.9.9.9".to_string(),
            ],
        }
    }
}

/// Journal persistence knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JournalSettings {
    /// `false` disables disk persistence; events still flow via broadcast.
    pub disk: bool,
    pub retention_days: u32,
    pub retention_count: u32,
}

impl Default for JournalSettings {
    fn default() -> Self {
        Self {
            disk: true,
            retention_days: 30,
            retention_count: 30,
        }
    }
}

/// Errors produced during `Settings::load`. Boxed for `clippy::result_large_err`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SettingsError {
    #[error("figment error: {0}")]
    Figment(Box<figment::Error>),
    #[error("I/O error resolving config path: {0}")]
    Io(#[from] std::io::Error),
    #[error("no usable config directory (XDG resolution failed)")]
    NoConfigDir,
    #[error(
        "settings schema version {found} is not supported by this build (max supported: {supported_max}). Upgrade vortix or migrate the file."
    )]
    UnsupportedSchema { found: u32, supported_max: u32 },
    #[error("invalid lifecycle hook configuration: {0}")]
    InvalidHook(#[from] HookConfigError),
}

impl From<figment::Error> for SettingsError {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

impl Settings {
    /// Load `<config_dir>/settings.toml` over `engine` defaults, then the
    /// `VORTIX_*` environment. The config dir is the same one that selects
    /// profiles and `config.toml`.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsError`] when the file or environment layer cannot be
    /// decoded, the schema is newer than this build, or a hook is invalid.
    pub fn load(config_dir: &Path, engine: EngineSettings) -> Result<Self, SettingsError> {
        let defaults = Self {
            engine,
            ..Self::default()
        };
        let mut fig = Figment::new().merge(Serialized::defaults(defaults));
        let user = config_dir.join("settings.toml");
        if user.exists() {
            fig = fig.merge(Toml::file(user));
        }
        let mut settings: Self = fig.merge(Env::prefixed("VORTIX_").split("__")).extract()?;
        if settings.schema_version > SETTINGS_SCHEMA_VERSION {
            return Err(SettingsError::UnsupportedSchema {
                found: settings.schema_version,
                supported_max: SETTINGS_SCHEMA_VERSION,
            });
        }
        settings.schema_version = SETTINGS_SCHEMA_VERSION;
        validate_hooks(&settings.hooks)?;
        Ok(settings)
    }
}

// === Lifecycle hooks ===

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
    use std::fs;

    fn load(body: Option<&str>) -> Result<Settings, SettingsError> {
        let dir = tempfile::tempdir().unwrap();
        if let Some(body) = body {
            fs::write(dir.path().join("settings.toml"), body).unwrap();
        }
        Settings::load(dir.path(), EngineSettings::default())
    }

    #[test]
    fn defaults_load_without_files() {
        let s = load(None).unwrap();
        assert_eq!(s.engine.connect_timeout_secs, 35);
        assert_eq!(s.engine.wireguard_handshake_timeout_secs, 20);
        assert_eq!(s.engine.wireguard_handshake_stale_secs, 180);
        assert!(!s.engine.wireguard_health_targets.is_empty());
        assert!(s.journal.disk);
        assert_eq!(s.journal.retention_days, 30);
        assert_eq!(s.schema_version, 1);
    }

    #[test]
    fn the_file_overrides_defaults_and_keeps_the_rest() {
        let s = load(Some(
            "[engine]\nconnect_timeout_secs = 60\n[journal]\ndisk = false\n",
        ))
        .unwrap();
        assert_eq!(s.engine.connect_timeout_secs, 60);
        assert!(!s.journal.disk);
        assert_eq!(s.journal.retention_days, 30);
    }

    #[test]
    fn an_old_file_with_removed_keys_still_loads() {
        let s = load(Some(
            "[engine]\nretry_budget_secs = 60\nconnect_timeout_secs = 50\n[ui]\nstart_mode = \"cli\"\n",
        ))
        .unwrap();
        assert_eq!(s.engine.connect_timeout_secs, 50);
    }

    #[test]
    fn invalid_hook_fails_the_settings_boundary() {
        assert!(matches!(
            load(Some(
                "[[hooks]]\nevent = \"connected\"\nexecutable = \"notify-send VPN-connected\"\n"
            )),
            Err(SettingsError::InvalidHook(_))
        ));
    }

    #[test]
    fn explicit_engine_settings_override_legacy_compatibility_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("settings.toml"),
            "[engine]\nwireguard_handshake_timeout_secs = 7\nwireguard_handshake_stale_secs = 91\nwireguard_health_targets = [\"10.0.0.1\"]\n",
        )
        .unwrap();
        let legacy = EngineSettings {
            wireguard_handshake_timeout_secs: 44,
            wireguard_handshake_stale_secs: 444,
            wireguard_health_targets: vec!["192.0.2.1".into()],
            ..EngineSettings::default()
        };
        let resolved = Settings::load(dir.path(), legacy).unwrap();
        assert_eq!(resolved.engine.wireguard_handshake_timeout_secs, 7);
        assert_eq!(resolved.engine.wireguard_handshake_stale_secs, 91);
        assert_eq!(resolved.engine.wireguard_health_targets, ["10.0.0.1"]);
    }

    #[test]
    fn old_partial_settings_keep_legacy_wireguard_values() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("settings.toml"),
            "[engine]\nconnect_timeout_secs = 60\n",
        )
        .unwrap();
        let legacy = EngineSettings {
            wireguard_handshake_timeout_secs: 44,
            wireguard_handshake_stale_secs: 444,
            wireguard_health_targets: vec!["192.0.2.1".into()],
            ..EngineSettings::default()
        };
        let resolved = Settings::load(dir.path(), legacy).unwrap();
        assert_eq!(resolved.engine.connect_timeout_secs, 60);
        assert_eq!(resolved.engine.wireguard_handshake_timeout_secs, 44);
        assert_eq!(resolved.engine.wireguard_handshake_stale_secs, 444);
        assert_eq!(resolved.engine.wireguard_health_targets, ["192.0.2.1"]);
    }

    #[test]
    fn invalid_toml_surfaces_error() {
        assert!(matches!(
            load(Some("[engine]\nconnect_timeout_secs = \"not a number\"\n")),
            Err(SettingsError::Figment(_))
        ));
    }

    #[test]
    fn schema_versions_zero_and_one_load_as_current() {
        for version in [0, 1] {
            let s = load(Some(&format!("schema_version = {version}\n"))).unwrap();
            assert_eq!(s.schema_version, SETTINGS_SCHEMA_VERSION);
        }
    }

    #[test]
    fn unsupported_schema_version_returns_typed_error() {
        match load(Some("schema_version = 999\n")).unwrap_err() {
            SettingsError::UnsupportedSchema {
                found,
                supported_max,
            } => {
                assert_eq!(found, 999);
                assert_eq!(supported_max, SETTINGS_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_hooks_load_as_absolute_argv_specs() {
        let settings = load(Some(
            "[[hooks]]\nevent = \"connected\"\nexecutable = \"/usr/bin/notify-send\"\nargs = [\"VPN connected\"]\ntimeout_secs = 7\n",
        ))
        .unwrap();
        assert_eq!(settings.hooks.len(), 1);
        assert_eq!(settings.hooks[0].timeout_secs, 7);
        assert_eq!(settings.hooks[0].event, crate::hooks::HookEvent::Connected);
    }

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
