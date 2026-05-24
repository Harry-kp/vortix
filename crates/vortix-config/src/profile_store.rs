//! `ProfileStore` trait + `FsProfileStore` impl (plan #006 U2).
//!
//! Filesystem-backed profile storage with sidecar metadata. Each profile
//! lives at `<profiles_dir>/<display_name>.<conf|ovpn>` with a sibling
//! `<display_name>.meta.toml` carrying stable identity, group, and timestamps.
//!
//! Plan 006 U4 lands the migration step that backfills sidecars for users
//! whose existing `.conf`/`.ovpn` files predate this scheme.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use vortix_core::profile::{Profile, ProfileId, ProtocolKind};

/// Errors returned by [`ProfileStore`] implementations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProfileStoreError {
    #[error("profile {0} not found")]
    NotFound(ProfileId),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed sidecar at {path}: {detail}")]
    MalformedSidecar { path: PathBuf, detail: String },
    #[error("sidecar serialisation failed: {0}")]
    SidecarSerialize(String),
    #[error("profile name {name} collides with an existing entry")]
    NameCollision { name: String },
}

/// Cheap-list summary returned by [`ProfileStore::list`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    pub group: Option<String>,
    pub last_used: Option<SystemTime>,
}

/// On-disk sidecar layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub schema_version: u32,
    pub profile_id: String,
    pub display_name: String,
    pub protocol: ProtocolKind,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub imported_at: Option<SystemTime>,
    #[serde(default)]
    pub last_used: Option<SystemTime>,
}

impl Sidecar {
    pub const SCHEMA_VERSION: u32 = 1;

    #[must_use]
    pub fn for_profile(p: &Profile) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            profile_id: p.id.as_str().to_string(),
            display_name: p.display_name.clone(),
            protocol: p.protocol,
            group: None,
            source: None,
            imported_at: Some(SystemTime::now()),
            last_used: None,
        }
    }
}

/// The profile-storage port.
pub trait ProfileStore {
    /// Cheap summary list — does NOT parse profile bodies.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileStoreError::Io`] when the profiles directory can't
    /// be read.
    fn list(&self) -> Result<Vec<ProfileSummary>, ProfileStoreError>;

    /// Load a profile by id.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileStoreError::NotFound`] when no matching sidecar
    /// exists; [`ProfileStoreError::Io`] on read failures.
    fn get(&self, id: &ProfileId) -> Result<Profile, ProfileStoreError>;

    /// Insert (or update) a profile. The `raw_body` is the `.conf`/`.ovpn`
    /// file contents.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileStoreError::Io`] on write failures or
    /// [`ProfileStoreError::NameCollision`] when an unrelated profile
    /// already owns the chosen `display_name`.
    fn insert(&self, profile: &Profile, raw_body: &[u8]) -> Result<(), ProfileStoreError>;

    /// Mark `last_used = now()`.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileStoreError::NotFound`] if the profile is missing.
    fn touch(&self, id: &ProfileId) -> Result<(), ProfileStoreError>;

    /// Delete the profile, sidecar, and any related run-files.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileStoreError::Io`] on filesystem failures.
    fn delete(&self, id: &ProfileId) -> Result<(), ProfileStoreError>;
}

/// Filesystem-backed implementation.
#[derive(Debug, Clone)]
pub struct FsProfileStore {
    pub profiles_dir: PathBuf,
}

impl FsProfileStore {
    #[must_use]
    pub fn new(profiles_dir: PathBuf) -> Self {
        Self { profiles_dir }
    }

    fn extension(protocol: ProtocolKind) -> &'static str {
        match protocol {
            ProtocolKind::OpenVpn => "ovpn",
            // WireGuard + future protocols default to .conf.
            _ => "conf",
        }
    }

    fn config_path(&self, display_name: &str, protocol: ProtocolKind) -> PathBuf {
        self.profiles_dir
            .join(format!("{display_name}.{}", Self::extension(protocol)))
    }

    fn sidecar_path(&self, display_name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{display_name}.meta.toml"))
    }

    fn read_sidecar(path: &Path) -> Result<Sidecar, ProfileStoreError> {
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).map_err(|e| ProfileStoreError::MalformedSidecar {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })
    }

    fn write_sidecar(path: &Path, sidecar: &Sidecar) -> Result<(), ProfileStoreError> {
        let text = toml::to_string_pretty(sidecar)
            .map_err(|e| ProfileStoreError::SidecarSerialize(e.to_string()))?;
        // Atomic-ish write: write to .tmp, rename.
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl ProfileStore for FsProfileStore {
    fn list(&self) -> Result<Vec<ProfileSummary>, ProfileStoreError> {
        let mut out = Vec::new();
        if !self.profiles_dir.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".meta.toml") {
                continue;
            }
            let sidecar = Self::read_sidecar(&path)?;
            out.push(ProfileSummary {
                id: ProfileId::new(&sidecar.profile_id),
                display_name: sidecar.display_name,
                protocol: sidecar.protocol,
                group: sidecar.group,
                last_used: sidecar.last_used,
            });
        }
        Ok(out)
    }

    fn get(&self, id: &ProfileId) -> Result<Profile, ProfileStoreError> {
        for summary in self.list()? {
            if &summary.id == id {
                return Ok(Profile::new(
                    summary.id,
                    summary.display_name.clone(),
                    summary.protocol,
                    self.config_path(&summary.display_name, summary.protocol),
                ));
            }
        }
        Err(ProfileStoreError::NotFound(id.clone()))
    }

    fn insert(&self, profile: &Profile, raw_body: &[u8]) -> Result<(), ProfileStoreError> {
        std::fs::create_dir_all(&self.profiles_dir)?;
        let cfg_path = self.config_path(&profile.display_name, profile.protocol);
        let meta_path = self.sidecar_path(&profile.display_name);

        // Detect collision with a different profile_id owning the same name.
        if meta_path.exists() {
            let existing = Self::read_sidecar(&meta_path)?;
            if existing.profile_id != profile.id.as_str() {
                return Err(ProfileStoreError::NameCollision {
                    name: profile.display_name.clone(),
                });
            }
        }

        // Atomic-ish writes.
        let cfg_tmp = cfg_path.with_extension(format!("{}.tmp", Self::extension(profile.protocol)));
        std::fs::write(&cfg_tmp, raw_body)?;
        std::fs::rename(&cfg_tmp, &cfg_path)?;

        Self::write_sidecar(&meta_path, &Sidecar::for_profile(profile))?;
        Ok(())
    }

    fn touch(&self, id: &ProfileId) -> Result<(), ProfileStoreError> {
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".meta.toml") {
                continue;
            }
            let mut sidecar = Self::read_sidecar(&path)?;
            if sidecar.profile_id == id.as_str() {
                sidecar.last_used = Some(SystemTime::now());
                Self::write_sidecar(&path, &sidecar)?;
                return Ok(());
            }
        }
        Err(ProfileStoreError::NotFound(id.clone()))
    }

    fn delete(&self, id: &ProfileId) -> Result<(), ProfileStoreError> {
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".meta.toml") {
                continue;
            }
            let sidecar = Self::read_sidecar(&path)?;
            if sidecar.profile_id == id.as_str() {
                let cfg = self.config_path(&sidecar.display_name, sidecar.protocol);
                let _ = std::fs::remove_file(&cfg);
                std::fs::remove_file(&path)?;
                return Ok(());
            }
        }
        Err(ProfileStoreError::NotFound(id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corp() -> Profile {
        Profile::new(
            ProfileId::new("corp-h1"),
            "corp",
            ProtocolKind::WireGuard,
            PathBuf::from("placeholder"),
        )
    }

    #[test]
    fn insert_then_list_then_get() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        store.insert(&corp(), b"[Interface]\n").unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id.as_str(), "corp-h1");
        assert_eq!(list[0].display_name, "corp");

        let p = store.get(&ProfileId::new("corp-h1")).unwrap();
        assert_eq!(p.display_name, "corp");
        assert_eq!(p.protocol, ProtocolKind::WireGuard);
        assert!(p.config_path.exists());
    }

    #[test]
    fn touch_updates_last_used() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        store.insert(&corp(), b"[Interface]\n").unwrap();

        assert!(store.list().unwrap()[0].last_used.is_none());
        store.touch(&ProfileId::new("corp-h1")).unwrap();
        assert!(store.list().unwrap()[0].last_used.is_some());
    }

    #[test]
    fn delete_removes_both_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        store.insert(&corp(), b"[Interface]\n").unwrap();
        store.delete(&ProfileId::new("corp-h1")).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn insert_with_same_id_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        store.insert(&corp(), b"[Interface]\n").unwrap();
        // Same id, same name — should succeed (idempotent re-import).
        store
            .insert(&corp(), b"[Interface]\nDifferent = true\n")
            .unwrap();
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn name_collision_with_different_id_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        store.insert(&corp(), b"[Interface]\n").unwrap();
        let other = Profile::new(
            ProfileId::new("different-id"),
            "corp",
            ProtocolKind::WireGuard,
            PathBuf::from("ignored"),
        );
        let err = store.insert(&other, b"[Interface]\n").unwrap_err();
        assert!(matches!(err, ProfileStoreError::NameCollision { .. }));
    }
}
