//! `vortix-config`: settings and profile store for vortix.
//!
//! Plan 006 populates this crate with:
//! - [`settings::Settings`] (U1) — figment-layered resolution of defaults →
//!   system file → user file → env → CLI.
//! - [`profile_store::ProfileStore`] (U2) — filesystem-backed profile storage
//!   with sidecar metadata.

#![allow(clippy::missing_errors_doc)]

pub mod error;
pub mod migration;
pub mod profile_store;
pub mod settings;

pub use error::ConfigError;
pub use migration::{migrate_legacy_profiles, MigrationStats};
pub use profile_store::{ProfileStore, ProfileStoreError, ProfileSummary};
pub use settings::{EngineSettings, JournalSettings, Settings, SettingsError, UiSettings};
