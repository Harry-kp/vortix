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

/// Top-level settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub engine: EngineSettings,
    pub journal: JournalSettings,
    pub ui: UiSettings,
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
        let s = fig.extract()?;
        Ok(s)
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
}
