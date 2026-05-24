//! `vortix-config`: settings, profile store, and secret store for vortix.
//!
//! Plan 006 populates this crate with:
//! - [`settings::Settings`] (U1) — figment-layered resolution of defaults →
//!   system file → user file → env → CLI.
//! - [`profile_store::ProfileStore`] (U2) — filesystem-backed profile storage
//!   with sidecar metadata.
//! - [`secret_store::SecretStore`] (U3) — keyring-first secret storage with
//!   encrypted-file fallback.
//!
//! Plan 006's remaining units (U4 migration, U5 tunnel-secret integration,
//! U7 main.rs wire-up) land in subsequent commits.

#![allow(clippy::missing_errors_doc)]

pub mod error;
pub mod hooks_config;
pub mod hooks_writer;
pub mod migration;
pub mod profile_store;
pub mod secret_store;
pub mod settings;

pub use error::ConfigError;
pub use hooks_config::{HookConfig, HooksList};
pub use hooks_writer::{write_hooks, write_hooks_with_mtime_check, HooksWriteError};
pub use migration::{migrate_legacy_profiles, MigrationStats};
pub use profile_store::{ProfileStore, ProfileStoreError, ProfileSummary};
pub use secret_store::{LayeredSecretStore, Secret, SecretRef, SecretStore, SecretStoreError};
pub use settings::{EngineSettings, JournalSettings, Settings, SettingsError, UiSettings};
