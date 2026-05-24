//! `Settings` struct + figment-layered resolution (plan #006 U1).
//!
//! Layer precedence (last wins): defaults → `/etc/vortix/config.toml` →
//! user file (`${XDG_CONFIG_HOME}/vortix/settings.toml`, SUDO_USER-aware) →
//! `VORTIX_*` env vars → CLI overrides.

use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current schema version for `settings.toml` (plan 008 U3).
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
    /// Schema version of the user's `settings.toml`. When this differs
    /// from [`SETTINGS_SCHEMA_VERSION`], [`migrate_settings`] is invoked
    /// to upgrade. Files without an explicit field default to 1.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub engine: EngineSettings,
    pub journal: JournalSettings,
    pub ui: UiSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            engine: EngineSettings::default(),
            journal: JournalSettings::default(),
            ui: UiSettings::default(),
        }
    }
}

/// Engine retry + reconnect knobs. Plan 005's FSM consumes these.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineSettings {
    /// Overall budget for connect + reconnect attempts.
    pub retry_budget_secs: u64,
    /// Initial backoff before the first retry; doubles each attempt.
    pub retry_initial_backoff_ms: u64,
    /// Default `OpenVPN --verb` value.
    pub openvpn_verbosity: String,
    /// Connect timeout used by `OvpnTunnel::with_connect_timeout`.
    pub connect_timeout_secs: u64,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            retry_budget_secs: 300,
            retry_initial_backoff_ms: 2_000,
            openvpn_verbosity: "3".to_string(),
            connect_timeout_secs: 30,
        }
    }
}

/// Journal persistence knobs. Plan 005's `Journal` consumes these.
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

/// UI / startup defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    pub start_mode: StartMode,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            start_mode: StartMode::Tui,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    Tui,
    Cli,
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
}

/// Migrate a parsed `Settings` from an older schema version to the
/// current [`SETTINGS_SCHEMA_VERSION`] (plan 008 U3).
///
/// v0.3.0 only knows `schema_version` = 1; older or newer versions
/// return `UnsupportedSchema`. Future versions will add upgrade arms
/// here.
///
/// # Errors
///
/// Returns [`SettingsError::UnsupportedSchema`] when the input's
/// `schema_version` is not handled by this build.
pub fn migrate_settings(mut s: Settings) -> Result<Settings, SettingsError> {
    match s.schema_version {
        0 | 1 => {
            // v0 ⇒ treat as v1 (older files didn't carry the field;
            // serde default reads as 1 anyway, but cover the 0 case for
            // explicit-zero writes).
            s.schema_version = SETTINGS_SCHEMA_VERSION;
            Ok(s)
        }
        found => Err(SettingsError::UnsupportedSchema {
            found,
            supported_max: SETTINGS_SCHEMA_VERSION,
        }),
    }
}

impl From<figment::Error> for SettingsError {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

impl Settings {
    /// Default loader: discover the user config path, merge in standard
    /// system + env layers, return the resolved `Settings`.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsError`] when a layer fails to parse or the user
    /// config dir cannot be resolved.
    pub fn load() -> Result<Self, SettingsError> {
        let user_path = user_config_path()?;
        Self::load_from(None, Some(&user_path))
    }

    /// Same as [`Self::load`] but with explicit `system` and `user` paths
    /// (`None` skips that layer). Useful for tests.
    ///
    /// # Errors
    ///
    /// Returns [`SettingsError::Figment`] when a present layer fails to
    /// parse.
    pub fn load_from(system: Option<&Path>, user: Option<&Path>) -> Result<Self, SettingsError> {
        let mut fig = Figment::new().merge(Serialized::defaults(Self::default()));
        if let Some(p) = system {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }
        if let Some(p) = user {
            if p.exists() {
                fig = fig.merge(Toml::file(p));
            }
        }
        fig = fig.merge(Env::prefixed("VORTIX_").split("__"));
        let s: Self = fig.extract()?;
        // Plan 008 U3: route through migrate_settings so an unsupported
        // schema_version surfaces as a typed error instead of silently
        // accepting unknown fields.
        migrate_settings(s)
    }
}

/// Resolve `${XDG_CONFIG_HOME}/vortix/settings.toml` with `SUDO_USER` awareness.
///
/// When running under `sudo` we want the *invoking* user's config, not
/// root's — mirrors the existing binary-side `resolve_config_dir`.
pub fn user_config_path() -> Result<PathBuf, SettingsError> {
    use directories::ProjectDirs;

    // If we're root and SUDO_USER is set, resolve the user dir manually.
    #[cfg(unix)]
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            if let Some(home) = sudo_home(&sudo_user) {
                return Ok(home.join(".config").join("vortix").join("settings.toml"));
            }
        }
    }

    let pd = ProjectDirs::from("", "", "vortix").ok_or(SettingsError::NoConfigDir)?;
    Ok(pd.config_dir().join("settings.toml"))
}

#[cfg(unix)]
fn sudo_home(user: &str) -> Option<PathBuf> {
    // /etc/passwd-style lookup via getpwnam would be heavier; use `$HOME`
    // fallback (the user's interactive shell sets it).
    if std::env::var("USER").as_deref() == Ok(user) {
        return std::env::var("HOME").ok().map(PathBuf::from);
    }
    None
}

#[cfg(not(unix))]
fn sudo_home(_user: &str) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn defaults_load_without_files() {
        let s = Settings::load_from(None, None).unwrap();
        assert_eq!(s.engine.retry_budget_secs, 300);
        assert_eq!(s.engine.retry_initial_backoff_ms, 2_000);
        assert!(s.journal.disk);
        assert_eq!(s.journal.retention_days, 30);
    }

    #[test]
    fn user_file_overrides_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.toml");
        fs::write(
            &path,
            "
[engine]
retry_budget_secs = 60
[journal]
disk = false
",
        )
        .unwrap();

        let s = Settings::load_from(None, Some(&path)).unwrap();
        assert_eq!(s.engine.retry_budget_secs, 60);
        assert!(!s.journal.disk);
        // Other fields keep defaults.
        assert_eq!(s.journal.retention_days, 30);
    }

    #[test]
    fn user_file_overrides_system_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = tmp.path().join("system.toml");
        let user = tmp.path().join("user.toml");
        fs::write(&sys, "[engine]\nretry_budget_secs = 60\n").unwrap();
        fs::write(&user, "[engine]\nretry_budget_secs = 120\n").unwrap();

        let s = Settings::load_from(Some(&sys), Some(&user)).unwrap();
        assert_eq!(s.engine.retry_budget_secs, 120);
    }

    #[test]
    fn invalid_toml_surfaces_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.toml");
        fs::write(&path, "[engine]\nretry_budget_secs = \"not a number\"\n").unwrap();
        let err = Settings::load_from(None, Some(&path)).unwrap_err();
        assert!(matches!(err, SettingsError::Figment(_)));
    }

    // Plan 008 U3 — schema_version + migration coverage.

    #[test]
    fn schema_version_defaults_to_one() {
        let s = Settings::load_from(None, None).unwrap();
        assert_eq!(s.schema_version, 1);
    }

    #[test]
    fn missing_schema_version_in_file_defaults_to_one() {
        // Pre-008 settings files don't carry schema_version; they
        // should load as v1 via the serde default.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("legacy.toml");
        fs::write(&path, "[engine]\nretry_budget_secs = 60\n").unwrap();
        let s = Settings::load_from(None, Some(&path)).unwrap();
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.engine.retry_budget_secs, 60);
    }

    #[test]
    fn explicit_schema_version_one_loads_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("v1.toml");
        fs::write(
            &path,
            "schema_version = 1\n[engine]\nretry_budget_secs = 90\n",
        )
        .unwrap();
        let s = Settings::load_from(None, Some(&path)).unwrap();
        assert_eq!(s.schema_version, 1);
        assert_eq!(s.engine.retry_budget_secs, 90);
    }

    #[test]
    fn unsupported_schema_version_returns_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("v999.toml");
        fs::write(&path, "schema_version = 999\n").unwrap();
        let err = Settings::load_from(None, Some(&path)).unwrap_err();
        match err {
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
    fn migrate_settings_normalises_zero_to_current() {
        // schema_version = 0 (older serializer write) is accepted and
        // normalised to the current version, preserving other fields.
        let engine = EngineSettings {
            retry_budget_secs: 42,
            ..EngineSettings::default()
        };
        let s = Settings {
            schema_version: 0,
            engine,
            journal: JournalSettings::default(),
            ui: UiSettings::default(),
        };
        let migrated = migrate_settings(s).unwrap();
        assert_eq!(migrated.schema_version, SETTINGS_SCHEMA_VERSION);
        assert_eq!(migrated.engine.retry_budget_secs, 42);
    }
}
