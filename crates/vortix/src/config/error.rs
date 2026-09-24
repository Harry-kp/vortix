//! Top-level config errors.

use thiserror::Error;

/// Umbrella error type for the config crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("settings error: {0}")]
    Settings(#[from] crate::config::settings::SettingsError),
    #[error("profile store error: {0}")]
    ProfileStore(#[from] crate::config::profile_store::ProfileStoreError),
}
