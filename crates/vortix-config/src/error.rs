//! Top-level config errors.

use thiserror::Error;

/// Umbrella error type for the config crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("settings error: {0}")]
    Settings(#[from] crate::settings::SettingsError),
    #[error("profile store error: {0}")]
    ProfileStore(#[from] crate::profile_store::ProfileStoreError),
    #[error("secret store error: {0}")]
    SecretStore(#[from] crate::secret_store::SecretStoreError),
}
