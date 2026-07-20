//! Sidecar-backed profile storage and recoverable identity-preserving rename.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::vortix_core::profile::{
    sanitize_profile_name, Profile, ProfileId, ProfileIdError, ProtocolKind,
};

const RENAME_INTENT: &str = ".vortix-profile-rename.toml";
const INSERT_INTENT: &str = ".vortix-profile-insert.toml";
const INSERT_STAGING: &str = ".vortix-profile-insert.config";
const DELETE_INTENT: &str = ".vortix-profile-delete.toml";
const PROFILE_LOCK: &str = ".vortix-profile.lock";
const LOCK_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) struct ProfileMutationLock(std::fs::File);

impl Drop for ProfileMutationLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: `flock` only consumes the valid descriptor owned by
            // this guard. Unlock failure is non-actionable during Drop.
            #[allow(unsafe_code)]
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

pub(crate) fn acquire_profile_lock(
    profiles_dir: &Path,
) -> Result<ProfileMutationLock, ProfileStoreError> {
    reject_symlink(profiles_dir)?;
    if let Some(parent) = profiles_dir.parent() {
        reject_symlink(parent)?;
    }
    std::fs::create_dir_all(profiles_dir)?;
    let path = profiles_dir.join(PROFILE_LOCK);
    reject_symlink(&path)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        // SAFETY: the descriptor remains owned by the returned guard for the
        // full lock lifetime; `flock` does not access Rust memory.
        #[allow(unsafe_code)]
        let started = Instant::now();
        loop {
            // SAFETY: as above; non-blocking acquisition keeps callers from
            // hanging forever behind another CLI/TUI process.
            #[allow(unsafe_code)]
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EWOULDBLOCK)
                && error.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(error.into());
            }
            if started.elapsed() >= LOCK_TIMEOUT {
                return Err(ProfileStoreError::LockBusy {
                    path: profiles_dir.to_path_buf(),
                });
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Ok(ProfileMutationLock(file))
}

/// Errors returned by [`ProfileStore`] implementations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProfileStoreError {
    #[error("profile {0} not found")]
    NotFound(ProfileId),
    #[error("profile named {0} not found")]
    DisplayNameNotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed sidecar at {path}: {detail}")]
    MalformedSidecar { path: PathBuf, detail: String },
    #[error("sidecar serialisation failed: {0}")]
    SidecarSerialize(String),
    #[error("profile name {name} collides with an existing entry")]
    NameCollision { name: String },
    #[error("duplicate profile ID {id} in {first} and {second}")]
    DuplicateId {
        id: ProfileId,
        first: PathBuf,
        second: PathBuf,
    },
    #[error("profile config {config} has no sidecar")]
    MissingSidecar { config: PathBuf },
    #[error("profile sidecar {sidecar} has no matching config {config}")]
    MissingConfig { sidecar: PathBuf, config: PathBuf },
    #[error("invalid profile name: {0}")]
    InvalidName(String),
    #[error("invalid profile ID: {0}")]
    InvalidId(String),
    #[error("profile storage is busy: timed out waiting for {path}")]
    LockBusy { path: PathBuf },
}

impl From<ProfileIdError> for ProfileStoreError {
    fn from(error: ProfileIdError) -> Self {
        Self::InvalidId(error.to_string())
    }
}

/// Cheap-list summary returned by [`ProfileStore::list`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    pub config_file: String,
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
    pub config_file: Option<String>,
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
    pub fn for_profile(profile: &Profile) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            profile_id: profile.id.as_str().to_string(),
            display_name: profile.display_name.clone(),
            protocol: profile.protocol,
            config_file: None,
            group: None,
            source: None,
            imported_at: Some(SystemTime::now()),
            last_used: None,
        }
    }
}

/// The profile-storage port.
pub trait ProfileStore {
    fn list(&self) -> Result<Vec<ProfileSummary>, ProfileStoreError>;
    fn get(&self, id: &ProfileId) -> Result<Profile, ProfileStoreError>;
    fn resolve_display_name(&self, name: &str) -> Result<ProfileId, ProfileStoreError>;
    fn insert(&self, profile: &Profile, raw_body: &[u8]) -> Result<(), ProfileStoreError>;
    fn touch(&self, id: &ProfileId) -> Result<(), ProfileStoreError>;
    fn rename(&self, id: &ProfileId, new_name: &str) -> Result<Profile, ProfileStoreError>;
    fn delete(&self, id: &ProfileId) -> Result<(), ProfileStoreError>;
}

/// Filesystem-backed implementation.
#[derive(Debug, Clone)]
pub struct FsProfileStore {
    pub profiles_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum RenameStage {
    Prepared,
    ConfigMoved,
    SidecarMoved,
    SidecarUpdated,
    AuthMoved,
    MetadataUpdated,
    InventoryUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameIntent {
    profile_id: ProfileId,
    old_name: String,
    new_name: String,
    protocol: ProtocolKind,
    old_config_file: String,
    new_config_file: String,
    stage: RenameStage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum InsertStage {
    Prepared,
    ConfigWritten,
    SidecarWritten,
    InventoryUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InsertIntent {
    profile_id: ProfileId,
    display_name: String,
    protocol: ProtocolKind,
    config_file: String,
    stage: InsertStage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum DeleteStage {
    Prepared,
    ConfigDeleted,
    SidecarDeleted,
    AuthDeleted,
    MetadataUpdated,
    InventoryUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteIntent {
    profile_id: ProfileId,
    display_name: String,
    protocol: ProtocolKind,
    config_file: String,
    stage: DeleteStage,
}

impl FsProfileStore {
    #[must_use]
    pub fn new(profiles_dir: PathBuf) -> Self {
        Self { profiles_dir }
    }

    /// Resume any durable profile transaction before inventory validation.
    pub fn recover_pending_transactions(&self) -> Result<(), ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        self.recover_pending_transactions_guarded(&lock)
    }

    pub(crate) fn recover_pending_transactions_guarded(
        &self,
        _lock: &ProfileMutationLock,
    ) -> Result<(), ProfileStoreError> {
        self.validate_root()?;
        self.recover_pending_insert()?;
        self.recover_pending_rename()?;
        self.recover_pending_delete()
    }

    fn extension(protocol: ProtocolKind) -> &'static str {
        match protocol {
            ProtocolKind::OpenVpn => "ovpn",
            ProtocolKind::WireGuard => "conf",
        }
    }

    fn config_path(&self, display_name: &str, protocol: ProtocolKind) -> PathBuf {
        self.profiles_dir
            .join(format!("{display_name}.{}", Self::extension(protocol)))
    }

    fn sidecar_path(&self, display_name: &str) -> PathBuf {
        self.profiles_dir.join(format!("{display_name}.meta.toml"))
    }

    fn sidecar_config_path(&self, sidecar: &Sidecar) -> PathBuf {
        sidecar.config_file.as_ref().map_or_else(
            || self.config_path(&sidecar.display_name, sidecar.protocol),
            |file| self.profiles_dir.join(file),
        )
    }

    fn insertion_config_file(&self, profile: &Profile) -> String {
        let is_local_named_path = profile.config_path.parent() == Some(self.profiles_dir.as_path())
            && profile
                .config_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                == Some(profile.display_name.as_str());
        if is_local_named_path
            && matches!(
                profile
                    .config_path
                    .extension()
                    .and_then(|value| value.to_str()),
                Some("conf" | "ovpn")
            )
        {
            profile
                .config_path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_string()
        } else {
            format!(
                "{}.{}",
                profile.display_name,
                Self::extension(profile.protocol)
            )
        }
    }

    fn root_dir(&self) -> PathBuf {
        self.profiles_dir
            .parent()
            .unwrap_or(&self.profiles_dir)
            .to_path_buf()
    }

    fn auth_path(&self, id: &ProfileId) -> PathBuf {
        self.root_dir()
            .join("auth")
            .join(format!("{}.auth", id.as_str()))
    }

    fn legacy_auth_path(&self, display_name: &str) -> Option<PathBuf> {
        (sanitize_profile_name(display_name) == display_name).then(|| {
            self.root_dir()
                .join("auth")
                .join(format!("{display_name}.auth"))
        })
    }

    fn intent_path(&self) -> PathBuf {
        self.profiles_dir.join(RENAME_INTENT)
    }

    fn insert_intent_path(&self) -> PathBuf {
        self.profiles_dir.join(INSERT_INTENT)
    }

    fn insert_staging_path(&self) -> PathBuf {
        self.profiles_dir.join(INSERT_STAGING)
    }

    fn delete_intent_path(&self) -> PathBuf {
        self.profiles_dir.join(DELETE_INTENT)
    }

    fn validate_root(&self) -> Result<(), ProfileStoreError> {
        reject_symlink(&self.profiles_dir)?;
        let root = self.root_dir();
        reject_symlink(&root)?;
        std::fs::create_dir_all(&self.profiles_dir)?;
        let auth = root.join("auth");
        if auth.exists() {
            reject_symlink(&auth)?;
        }
        Ok(())
    }

    fn safe_profile_path(&self, file: &str) -> Result<PathBuf, ProfileStoreError> {
        validate_basename(file)?;
        let path = self.profiles_dir.join(file);
        reject_symlink(&path)?;
        Ok(path)
    }

    pub(crate) fn read_sidecar(path: &Path) -> Result<Sidecar, ProfileStoreError> {
        reject_symlink(path)?;
        let text = std::fs::read_to_string(path)?;
        let sidecar: Sidecar =
            toml::from_str(&text).map_err(|error| ProfileStoreError::MalformedSidecar {
                path: path.to_path_buf(),
                detail: error.to_string(),
            })?;
        if sidecar.schema_version != Sidecar::SCHEMA_VERSION {
            return Err(ProfileStoreError::MalformedSidecar {
                path: path.to_path_buf(),
                detail: format!("unsupported schema version {}", sidecar.schema_version),
            });
        }
        ProfileId::parse(sidecar.profile_id.clone()).map_err(|error| {
            ProfileStoreError::MalformedSidecar {
                path: path.to_path_buf(),
                detail: error.to_string(),
            }
        })?;
        Self::validate_name(&sidecar.display_name)?;
        if let Some(config_file) = &sidecar.config_file {
            let config_path = Path::new(config_file);
            let safe_filename = config_path.components().count() == 1
                && config_path.file_stem().and_then(|stem| stem.to_str())
                    == Some(sidecar.display_name.as_str())
                && matches!(
                    config_path
                        .extension()
                        .and_then(|extension| extension.to_str()),
                    Some("conf" | "ovpn")
                );
            if !safe_filename {
                return Err(ProfileStoreError::MalformedSidecar {
                    path: path.to_path_buf(),
                    detail: "config_file must be a matching .conf/.ovpn basename".to_string(),
                });
            }
        }
        Ok(sidecar)
    }

    pub(crate) fn write_sidecar(path: &Path, sidecar: &Sidecar) -> Result<(), ProfileStoreError> {
        let text = toml::to_string_pretty(sidecar)
            .map_err(|error| ProfileStoreError::SidecarSerialize(error.to_string()))?;
        write_atomic(path, text.as_bytes())?;
        Ok(())
    }

    fn validate_name(name: &str) -> Result<(), ProfileStoreError> {
        if name.trim() != name
            || name.is_empty()
            || name.starts_with('.')
            || name.contains('/')
            || name.contains('\\')
            || name.contains("..")
        {
            return Err(ProfileStoreError::InvalidName(name.to_string()));
        }
        Ok(())
    }

    fn recover_pending_rename(&self) -> Result<(), ProfileStoreError> {
        let path = self.intent_path();
        if !path.exists() {
            return Ok(());
        }
        let text = std::fs::read_to_string(&path)?;
        let mut intent: RenameIntent =
            toml::from_str(&text).map_err(|error| ProfileStoreError::MalformedSidecar {
                path: path.clone(),
                detail: format!("malformed rename intent: {error}"),
            })?;
        self.validate_rename_intent(&intent)?;
        self.resume_rename(&mut intent)
    }

    fn save_intent(&self, intent: &RenameIntent) -> Result<(), ProfileStoreError> {
        let text = toml::to_string_pretty(intent)
            .map_err(|error| ProfileStoreError::SidecarSerialize(error.to_string()))?;
        write_atomic(&self.intent_path(), text.as_bytes())?;
        Ok(())
    }

    fn validate_rename_intent(&self, intent: &RenameIntent) -> Result<(), ProfileStoreError> {
        Self::validate_name(&intent.old_name)?;
        Self::validate_name(&intent.new_name)?;
        validate_config_basename(&intent.old_config_file, &intent.old_name)?;
        validate_config_basename(&intent.new_config_file, &intent.new_name)?;
        if Path::new(&intent.old_config_file).extension()
            != Path::new(&intent.new_config_file).extension()
        {
            return Err(ProfileStoreError::InvalidName(
                "rename intent changes config type".to_string(),
            ));
        }
        let old_sidecar = self.sidecar_path(&intent.old_name);
        let new_sidecar = self.sidecar_path(&intent.new_name);
        reject_symlink(&old_sidecar)?;
        reject_symlink(&new_sidecar)?;
        let sidecar = if old_sidecar.exists() {
            Some(Self::read_sidecar(&old_sidecar)?)
        } else if new_sidecar.exists() {
            Some(Self::read_sidecar(&new_sidecar)?)
        } else {
            None
        };
        if let Some(sidecar) = sidecar {
            if sidecar.profile_id != intent.profile_id.as_str()
                || sidecar.protocol != intent.protocol
                || !matches!(sidecar.display_name.as_str(), name if name == intent.old_name || name == intent.new_name)
                || sidecar.config_file.as_deref().is_some_and(|file| {
                    file != intent.old_config_file && file != intent.new_config_file
                })
            {
                return Err(ProfileStoreError::MalformedSidecar {
                    path: if old_sidecar.exists() {
                        old_sidecar
                    } else {
                        new_sidecar
                    },
                    detail: "rename intent does not match sidecar identity".to_string(),
                });
            }
        }
        Ok(())
    }

    fn resume_rename(&self, intent: &mut RenameIntent) -> Result<(), ProfileStoreError> {
        self.validate_rename_intent(intent)?;
        let old_config = self.safe_profile_path(&intent.old_config_file)?;
        let new_config = self.safe_profile_path(&intent.new_config_file)?;
        let old_sidecar = self.sidecar_path(&intent.old_name);
        let new_sidecar = self.sidecar_path(&intent.new_name);
        let auth = self.auth_path(&intent.profile_id);
        let legacy_auth = self.legacy_auth_path(&intent.old_name);
        reject_symlink(&auth)?;
        if let Some(path) = &legacy_auth {
            reject_symlink(path)?;
        }
        if intent.stage == RenameStage::Prepared {
            move_once(&old_config, &new_config)?;
            intent.stage = RenameStage::ConfigMoved;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::ConfigMoved {
            move_once(&old_sidecar, &new_sidecar)?;
            intent.stage = RenameStage::SidecarMoved;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::SidecarMoved {
            let mut sidecar = Self::read_sidecar(&new_sidecar)?;
            if sidecar.profile_id != intent.profile_id.as_str() {
                return Err(ProfileStoreError::MalformedSidecar {
                    path: new_sidecar.clone(),
                    detail: "rename intent ID does not match sidecar".to_string(),
                });
            }
            sidecar.display_name.clone_from(&intent.new_name);
            sidecar.config_file = Some(intent.new_config_file.clone());
            Self::write_sidecar(&new_sidecar, &sidecar)?;
            intent.stage = RenameStage::SidecarUpdated;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::SidecarUpdated {
            if let Some(legacy) = legacy_auth
                .as_ref()
                .filter(|path| path.as_path() != auth && path.exists())
            {
                if auth.exists() {
                    remove_if_exists(legacy)?;
                } else {
                    if let Some(parent) = auth.parent() {
                        reject_symlink(parent)?;
                        std::fs::create_dir_all(parent)?;
                    }
                    move_once(legacy, &auth)?;
                }
            }
            intent.stage = RenameStage::AuthMoved;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::AuthMoved {
            update_metadata_key(
                &self.root_dir().join("metadata.json"),
                &old_config,
                &new_config,
            )?;
            intent.stage = RenameStage::MetadataUpdated;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::MetadataUpdated {
            crate::vortix_config::migration::rename_inventory_entry(
                &self.profiles_dir,
                &intent.profile_id,
                &intent.new_name,
                &intent.new_config_file,
            )?;
            intent.stage = RenameStage::InventoryUpdated;
            self.save_intent(intent)?;
        }
        if intent.stage == RenameStage::InventoryUpdated {
            std::fs::remove_file(self.intent_path())?;
            sync_dir(&self.profiles_dir)?;
        }
        Ok(())
    }

    fn recover_pending_insert(&self) -> Result<(), ProfileStoreError> {
        let path = self.insert_intent_path();
        if !path.exists() {
            return Ok(());
        }
        reject_symlink(&path)?;
        let text = std::fs::read_to_string(&path)?;
        let mut intent: InsertIntent =
            toml::from_str(&text).map_err(|error| ProfileStoreError::MalformedSidecar {
                path: path.clone(),
                detail: format!("malformed insert intent: {error}"),
            })?;
        Self::validate_name(&intent.display_name)?;
        validate_config_basename(&intent.config_file, &intent.display_name)?;
        self.resume_insert(&mut intent)
    }

    fn save_insert_intent(&self, intent: &InsertIntent) -> Result<(), ProfileStoreError> {
        let body = toml::to_string_pretty(intent)
            .map_err(|error| ProfileStoreError::SidecarSerialize(error.to_string()))?;
        write_atomic(&self.insert_intent_path(), body.as_bytes())?;
        Ok(())
    }

    fn resume_insert(&self, intent: &mut InsertIntent) -> Result<(), ProfileStoreError> {
        let config = self.safe_profile_path(&intent.config_file)?;
        let sidecar_path = self.sidecar_path(&intent.display_name);
        reject_symlink(&sidecar_path)?;
        let staging = self.insert_staging_path();
        reject_symlink(&staging)?;
        if intent.stage == InsertStage::Prepared {
            move_once(&staging, &config)?;
            intent.stage = InsertStage::ConfigWritten;
            self.save_insert_intent(intent)?;
        }
        if intent.stage == InsertStage::ConfigWritten {
            let profile = Profile::new(
                intent.profile_id.clone(),
                intent.display_name.clone(),
                intent.protocol,
                config.clone(),
            );
            let mut sidecar = Sidecar::for_profile(&profile);
            sidecar.config_file = Some(intent.config_file.clone());
            Self::write_sidecar(&sidecar_path, &sidecar)?;
            intent.stage = InsertStage::SidecarWritten;
            self.save_insert_intent(intent)?;
        }
        if intent.stage == InsertStage::SidecarWritten {
            let profile = Profile::new(
                intent.profile_id.clone(),
                intent.display_name.clone(),
                intent.protocol,
                config,
            );
            crate::vortix_config::migration::insert_inventory_entry(&self.profiles_dir, &profile)?;
            intent.stage = InsertStage::InventoryUpdated;
            self.save_insert_intent(intent)?;
        }
        if intent.stage == InsertStage::InventoryUpdated {
            remove_if_exists(&self.insert_intent_path())?;
            remove_if_exists(&staging)?;
            sync_dir(&self.profiles_dir)?;
        }
        Ok(())
    }

    fn recover_pending_delete(&self) -> Result<(), ProfileStoreError> {
        let path = self.delete_intent_path();
        if !path.exists() {
            return Ok(());
        }
        reject_symlink(&path)?;
        let text = std::fs::read_to_string(&path)?;
        let mut intent: DeleteIntent =
            toml::from_str(&text).map_err(|error| ProfileStoreError::MalformedSidecar {
                path: path.clone(),
                detail: format!("malformed delete intent: {error}"),
            })?;
        Self::validate_name(&intent.display_name)?;
        validate_config_basename(&intent.config_file, &intent.display_name)?;
        if matches!(
            intent.stage,
            DeleteStage::Prepared | DeleteStage::ConfigDeleted
        ) {
            let sidecar_path = self.sidecar_path(&intent.display_name);
            let sidecar = Self::read_sidecar(&sidecar_path)?;
            if sidecar.profile_id != intent.profile_id.as_str()
                || sidecar.display_name != intent.display_name
                || sidecar.protocol != intent.protocol
                || sidecar
                    .config_file
                    .as_deref()
                    .is_some_and(|file| file != intent.config_file)
            {
                return Err(ProfileStoreError::MalformedSidecar {
                    path: sidecar_path,
                    detail: "delete intent does not match sidecar identity".to_string(),
                });
            }
        }
        self.resume_delete(&mut intent)
    }

    fn save_delete_intent(&self, intent: &DeleteIntent) -> Result<(), ProfileStoreError> {
        let body = toml::to_string_pretty(intent)
            .map_err(|error| ProfileStoreError::SidecarSerialize(error.to_string()))?;
        write_atomic(&self.delete_intent_path(), body.as_bytes())?;
        Ok(())
    }

    fn resume_delete(&self, intent: &mut DeleteIntent) -> Result<(), ProfileStoreError> {
        let config = self.safe_profile_path(&intent.config_file)?;
        let sidecar = self.sidecar_path(&intent.display_name);
        let auth = self.auth_path(&intent.profile_id);
        let legacy_auth = self.legacy_auth_path(&intent.display_name);
        reject_symlink(&sidecar)?;
        reject_symlink(&auth)?;
        if let Some(path) = &legacy_auth {
            reject_symlink(path)?;
        }
        if intent.stage == DeleteStage::Prepared {
            remove_if_exists(&config)?;
            intent.stage = DeleteStage::ConfigDeleted;
            self.save_delete_intent(intent)?;
        }
        if intent.stage == DeleteStage::ConfigDeleted {
            remove_if_exists(&sidecar)?;
            intent.stage = DeleteStage::SidecarDeleted;
            self.save_delete_intent(intent)?;
        }
        if intent.stage == DeleteStage::SidecarDeleted {
            remove_if_exists(&auth)?;
            if let Some(path) = &legacy_auth {
                remove_if_exists(path)?;
            }
            intent.stage = DeleteStage::AuthDeleted;
            self.save_delete_intent(intent)?;
        }
        if intent.stage == DeleteStage::AuthDeleted {
            remove_metadata_key(&self.root_dir().join("metadata.json"), &config)?;
            intent.stage = DeleteStage::MetadataUpdated;
            self.save_delete_intent(intent)?;
        }
        if intent.stage == DeleteStage::MetadataUpdated {
            crate::vortix_config::migration::delete_inventory_entry(
                &self.profiles_dir,
                &intent.profile_id,
            )?;
            intent.stage = DeleteStage::InventoryUpdated;
            self.save_delete_intent(intent)?;
        }
        if intent.stage == DeleteStage::InventoryUpdated {
            remove_if_exists(&self.delete_intent_path())?;
            sync_dir(&self.profiles_dir)?;
        }
        Ok(())
    }

    fn validated_sidecars_guarded(
        &self,
        _lock: &ProfileMutationLock,
    ) -> Result<Vec<(PathBuf, Sidecar, ProfileId)>, ProfileStoreError> {
        if !self.profiles_dir.exists() {
            return Ok(Vec::new());
        }
        let mut configs = HashSet::new();
        let mut sidecars = Vec::new();
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let path = entry?.path();
            reject_symlink(&path)?;
            if !path.is_file() {
                continue;
            }
            if let Some("conf" | "ovpn") = path.extension().and_then(|extension| extension.to_str())
            {
                reject_symlink(&path)?;
                configs.insert(path);
            }
        }

        let mut ids: HashMap<ProfileId, PathBuf> = HashMap::new();
        for entry in std::fs::read_dir(&self.profiles_dir)? {
            let path = entry?.path();
            reject_symlink(&path)?;
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if !name.ends_with(".meta.toml") {
                continue;
            }
            let sidecar = Self::read_sidecar(&path)?;
            Self::validate_name(&sidecar.display_name)?;
            if path.file_name().and_then(|name| name.to_str())
                != Some(format!("{}.meta.toml", sidecar.display_name).as_str())
            {
                return Err(ProfileStoreError::MalformedSidecar {
                    path,
                    detail: "sidecar filename does not match display_name".to_string(),
                });
            }
            let id = ProfileId::parse(sidecar.profile_id.clone()).map_err(|error| {
                ProfileStoreError::MalformedSidecar {
                    path: path.clone(),
                    detail: error.to_string(),
                }
            })?;
            if let Some(first) = ids.insert(id.clone(), path.clone()) {
                return Err(ProfileStoreError::DuplicateId {
                    id,
                    first,
                    second: path,
                });
            }
            let config = self.sidecar_config_path(&sidecar);
            if !configs.remove(&config) {
                return Err(ProfileStoreError::MissingConfig {
                    sidecar: path,
                    config,
                });
            }
            sidecars.push((path, sidecar, id));
        }
        if let Some(config) = configs.into_iter().next() {
            return Err(ProfileStoreError::MissingSidecar { config });
        }
        Ok(sidecars)
    }

    fn validated_sidecars(&self) -> Result<Vec<(PathBuf, Sidecar, ProfileId)>, ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        self.recover_pending_transactions_guarded(&lock)?;
        self.validated_sidecars_guarded(&lock)
    }
}

impl ProfileStore for FsProfileStore {
    fn list(&self) -> Result<Vec<ProfileSummary>, ProfileStoreError> {
        let mut summaries = self
            .validated_sidecars()?
            .into_iter()
            .map(|(_, sidecar, id)| {
                let config_file = sidecar.config_file.unwrap_or_else(|| {
                    format!(
                        "{}.{}",
                        sidecar.display_name,
                        Self::extension(sidecar.protocol)
                    )
                });
                ProfileSummary {
                    id,
                    display_name: sidecar.display_name,
                    protocol: sidecar.protocol,
                    config_file,
                    group: sidecar.group,
                    last_used: sidecar.last_used,
                }
            })
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| left.display_name.cmp(&right.display_name));
        Ok(summaries)
    }

    fn get(&self, id: &ProfileId) -> Result<Profile, ProfileStoreError> {
        self.list()?
            .into_iter()
            .find(|summary| &summary.id == id)
            .map(|summary| {
                Profile::new(
                    summary.id,
                    summary.display_name.clone(),
                    summary.protocol,
                    self.profiles_dir.join(summary.config_file),
                )
            })
            .ok_or_else(|| ProfileStoreError::NotFound(id.clone()))
    }

    fn resolve_display_name(&self, name: &str) -> Result<ProfileId, ProfileStoreError> {
        self.list()?
            .into_iter()
            .find(|summary| summary.display_name == name)
            .map(|summary| summary.id)
            .ok_or_else(|| ProfileStoreError::DisplayNameNotFound(name.to_string()))
    }

    fn insert(&self, profile: &Profile, raw_body: &[u8]) -> Result<(), ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        Self::validate_name(&profile.display_name)?;
        ProfileId::parse(profile.id.as_str().to_string())?;
        self.recover_pending_transactions_guarded(&lock)?;
        std::fs::create_dir_all(&self.profiles_dir)?;
        let config_file = self.insertion_config_file(profile);
        validate_config_basename(&config_file, &profile.display_name)?;
        let config = self.safe_profile_path(&config_file)?;
        let sidecar = self.sidecar_path(&profile.display_name);
        reject_symlink(&sidecar)?;
        let existing = self.validated_sidecars_guarded(&lock)?;
        if existing.iter().any(|(_, candidate, candidate_id)| {
            candidate_id != &profile.id && candidate.display_name == profile.display_name
        }) || config.exists()
            || sidecar.exists()
        {
            return Err(ProfileStoreError::NameCollision {
                name: profile.display_name.clone(),
            });
        }
        write_atomic(&self.insert_staging_path(), raw_body)?;
        let mut intent = InsertIntent {
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            protocol: profile.protocol,
            config_file,
            stage: InsertStage::Prepared,
        };
        self.save_insert_intent(&intent)?;
        self.resume_insert(&mut intent)?;
        self.validated_sidecars_guarded(&lock)?;
        Ok(())
    }

    fn touch(&self, id: &ProfileId) -> Result<(), ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        self.recover_pending_transactions_guarded(&lock)?;
        for (path, mut sidecar, candidate) in self.validated_sidecars_guarded(&lock)? {
            if &candidate == id {
                sidecar.last_used = Some(SystemTime::now());
                return Self::write_sidecar(&path, &sidecar);
            }
        }
        Err(ProfileStoreError::NotFound(id.clone()))
    }

    fn rename(&self, id: &ProfileId, new_name: &str) -> Result<Profile, ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        Self::validate_name(new_name)?;
        self.recover_pending_transactions_guarded(&lock)?;
        let profiles = self.validated_sidecars_guarded(&lock)?;
        let (_, sidecar, _) = profiles
            .iter()
            .find(|(_, _, candidate)| candidate == id)
            .ok_or_else(|| ProfileStoreError::NotFound(id.clone()))?;
        let config_file = sidecar.config_file.clone().unwrap_or_else(|| {
            format!(
                "{}.{}",
                sidecar.display_name,
                Self::extension(sidecar.protocol)
            )
        });
        let profile = Profile::new(
            id.clone(),
            sidecar.display_name.clone(),
            sidecar.protocol,
            self.safe_profile_path(&config_file)?,
        );
        if profile.display_name == new_name {
            return Ok(profile);
        }
        let extension = profile
            .config_path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_else(|| Self::extension(profile.protocol));
        let new_config_file = format!("{new_name}.{extension}");
        let new_config = self.safe_profile_path(&new_config_file)?;
        let new_sidecar = self.sidecar_path(new_name);
        if new_config.exists() || new_sidecar.exists() {
            return Err(ProfileStoreError::NameCollision {
                name: new_name.to_string(),
            });
        }
        let mut intent = RenameIntent {
            profile_id: id.clone(),
            old_name: profile.display_name.clone(),
            new_name: new_name.to_string(),
            protocol: profile.protocol,
            old_config_file: config_file,
            new_config_file,
            stage: RenameStage::Prepared,
        };
        self.save_intent(&intent)?;
        self.resume_rename(&mut intent)?;
        let (_, sidecar, stable_id) = self
            .validated_sidecars_guarded(&lock)?
            .into_iter()
            .find(|(_, _, candidate)| candidate == id)
            .ok_or_else(|| ProfileStoreError::NotFound(id.clone()))?;
        let config_path = self.sidecar_config_path(&sidecar);
        Ok(Profile::new(
            stable_id,
            sidecar.display_name,
            sidecar.protocol,
            config_path,
        ))
    }

    fn delete(&self, id: &ProfileId) -> Result<(), ProfileStoreError> {
        let lock = acquire_profile_lock(&self.profiles_dir)?;
        self.recover_pending_transactions_guarded(&lock)?;
        let profiles = self.validated_sidecars_guarded(&lock)?;
        let (_, sidecar, _) = profiles
            .into_iter()
            .find(|(_, _, candidate)| candidate == id)
            .ok_or_else(|| ProfileStoreError::NotFound(id.clone()))?;
        let config_file = sidecar.config_file.unwrap_or_else(|| {
            format!(
                "{}.{}",
                sidecar.display_name,
                Self::extension(sidecar.protocol)
            )
        });
        let mut intent = DeleteIntent {
            profile_id: id.clone(),
            display_name: sidecar.display_name,
            protocol: sidecar.protocol,
            config_file,
            stage: DeleteStage::Prepared,
        };
        self.save_delete_intent(&intent)?;
        self.resume_delete(&mut intent)
    }
}

fn move_once(source: &Path, destination: &Path) -> std::io::Result<()> {
    reject_symlink_io(source)?;
    reject_symlink_io(destination)?;
    match (source.exists(), destination.exists()) {
        (true, false) => std::fs::rename(source, destination),
        (false, true) => Ok(()),
        (true, true) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "both {} and {} exist",
                source.display(),
                destination.display()
            ),
        )),
        (false, false) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "neither {} nor {} exists",
                source.display(),
                destination.display()
            ),
        )),
    }
}

fn remove_if_exists(path: &Path) -> std::io::Result<()> {
    reject_symlink_io(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn update_metadata_key(path: &Path, old: &Path, new: &Path) -> std::io::Result<()> {
    reject_symlink_io(path)?;
    if !path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)?;
    let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if let Some(value) = map.remove(&old.to_string_lossy().to_string()) {
        map.insert(new.to_string_lossy().to_string(), value);
        let output = serde_json::to_vec_pretty(&map)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        write_atomic(path, &output)?;
    }
    Ok(())
}

fn remove_metadata_key(path: &Path, config: &Path) -> std::io::Result<()> {
    reject_symlink_io(path)?;
    if !path.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)?;
    let mut map: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if map.remove(&config.to_string_lossy().to_string()).is_some() {
        let output = serde_json::to_vec_pretty(&map)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        write_atomic(path, &output)?;
    }
    Ok(())
}

fn validate_basename(file: &str) -> Result<(), ProfileStoreError> {
    let path = Path::new(file);
    if file.is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || path.file_name().and_then(|value| value.to_str()) != Some(file)
        || matches!(file, "." | "..")
    {
        return Err(ProfileStoreError::InvalidName(file.to_string()));
    }
    Ok(())
}

fn validate_config_basename(file: &str, display_name: &str) -> Result<(), ProfileStoreError> {
    validate_basename(file)?;
    let path = Path::new(file);
    if path.file_stem().and_then(|value| value.to_str()) != Some(display_name)
        || !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("conf" | "ovpn")
        )
    {
        return Err(ProfileStoreError::InvalidName(file.to_string()));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), ProfileStoreError> {
    reject_symlink_io(path).map_err(ProfileStoreError::Io)
}

fn reject_symlink_io(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing symlink path {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    reject_symlink_io(parent)?;
    reject_symlink_io(path)?;
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!(
        "{}.{}.{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("file"),
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(body)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    sync_dir(parent)
}

fn sync_dir(path: &Path) -> std::io::Result<()> {
    FileSync::sync(path)
}

struct FileSync;

impl FileSync {
    #[cfg(unix)]
    fn sync(path: &Path) -> std::io::Result<()> {
        std::fs::File::open(path)?.sync_all()
    }

    #[cfg(not(unix))]
    fn sync(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> ProfileId {
        ProfileId::parse(format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn corp() -> Profile {
        Profile::new(
            id(1),
            "corp",
            ProtocolKind::WireGuard,
            PathBuf::from("placeholder"),
        )
    }

    #[test]
    fn insert_list_get_and_resolve_use_stable_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        assert_eq!(store.resolve_display_name("corp").unwrap(), id(1));
        assert_eq!(store.get(&id(1)).unwrap().display_name, "corp");
    }

    #[test]
    fn duplicate_ids_fail_validation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        std::fs::copy(store.sidecar_path("corp"), store.sidecar_path("home")).unwrap();
        std::fs::write(store.config_path("home", ProtocolKind::WireGuard), b"x").unwrap();
        let mut home = FsProfileStore::read_sidecar(&store.sidecar_path("home")).unwrap();
        home.display_name = "home".to_string();
        home.config_file = Some("home.conf".to_string());
        FsProfileStore::write_sidecar(&store.sidecar_path("home"), &home).unwrap();
        assert!(matches!(
            store.list(),
            Err(ProfileStoreError::DuplicateId { .. })
        ));
    }

    #[test]
    fn credential_keys_are_stable_ids_not_colliding_sanitized_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        let first = Profile::new(
            id(1),
            "a b",
            ProtocolKind::OpenVpn,
            PathBuf::from("placeholder"),
        );
        let second = Profile::new(
            id(2),
            "a?b",
            ProtocolKind::OpenVpn,
            PathBuf::from("placeholder"),
        );
        assert_eq!(
            sanitize_profile_name(&first.display_name),
            sanitize_profile_name(&second.display_name)
        );
        store.insert(&first, b"client\ndev tun\n").unwrap();
        store.insert(&second, b"client\ndev tun\n").unwrap();
        assert_ne!(store.auth_path(&id(1)), store.auth_path(&id(2)));
        assert_eq!(store.rename(&id(1), "a@b").unwrap().id, id(1));
        assert_eq!(store.list().unwrap().len(), 2);
    }

    #[test]
    fn rename_keeps_credentials_when_legacy_name_equals_stable_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        let stable_id = id(3);
        let profile = Profile::new(
            stable_id.clone(),
            stable_id.as_str(),
            ProtocolKind::OpenVpn,
            PathBuf::from("placeholder"),
        );
        store.insert(&profile, b"client\ndev tun\n").unwrap();
        let auth = store.auth_path(&stable_id);
        std::fs::create_dir_all(auth.parent().unwrap()).unwrap();
        std::fs::write(&auth, b"secret").unwrap();
        store.rename(&stable_id, "work").unwrap();
        assert_eq!(std::fs::read(&auth).unwrap(), b"secret");
    }

    #[test]
    fn rename_preserves_id_and_auth_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        let old_auth = store.legacy_auth_path("corp").unwrap();
        std::fs::create_dir_all(old_auth.parent().unwrap()).unwrap();
        std::fs::write(&old_auth, b"user\npassword\n").unwrap();
        let metadata = store.root_dir().join("metadata.json");
        std::fs::write(
            &metadata,
            format!(
                "{{\"{}\":{{\"last_used\":null}}}}",
                store.config_path("corp", ProtocolKind::WireGuard).display()
            ),
        )
        .unwrap();

        let renamed = store.rename(&id(1), "work").unwrap();
        assert_eq!(renamed.id, id(1));
        assert_eq!(renamed.display_name, "work");
        assert!(store.auth_path(&id(1)).exists());
        assert!(!old_auth.exists());
        assert!(std::fs::read_to_string(metadata)
            .unwrap()
            .contains("work.conf"));
    }

    #[test]
    fn rename_recovers_from_every_file_boundary_without_identity_split() {
        for stage in [
            RenameStage::Prepared,
            RenameStage::ConfigMoved,
            RenameStage::SidecarMoved,
            RenameStage::SidecarUpdated,
            RenameStage::AuthMoved,
            RenameStage::MetadataUpdated,
            RenameStage::InventoryUpdated,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let store = FsProfileStore::new(tmp.path().join("profiles"));
            std::fs::create_dir_all(&store.profiles_dir).unwrap();
            std::fs::write(store.profiles_dir.join("corp.conf"), b"[Interface]\n").unwrap();
            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            let stable_id = store.resolve_display_name("corp").unwrap();
            let old_auth = store.legacy_auth_path("corp").unwrap();
            std::fs::create_dir_all(old_auth.parent().unwrap()).unwrap();
            std::fs::write(&old_auth, b"secret").unwrap();
            let mut intent = RenameIntent {
                profile_id: stable_id.clone(),
                old_name: "corp".to_string(),
                new_name: "work".to_string(),
                protocol: ProtocolKind::WireGuard,
                old_config_file: "corp.conf".to_string(),
                new_config_file: "work.conf".to_string(),
                stage,
            };
            if stage != RenameStage::Prepared {
                move_once(
                    &store.config_path("corp", ProtocolKind::WireGuard),
                    &store.config_path("work", ProtocolKind::WireGuard),
                )
                .unwrap();
            }
            if matches!(
                stage,
                RenameStage::SidecarMoved
                    | RenameStage::SidecarUpdated
                    | RenameStage::AuthMoved
                    | RenameStage::MetadataUpdated
                    | RenameStage::InventoryUpdated
            ) {
                move_once(&store.sidecar_path("corp"), &store.sidecar_path("work")).unwrap();
            }
            if matches!(
                stage,
                RenameStage::SidecarUpdated
                    | RenameStage::AuthMoved
                    | RenameStage::MetadataUpdated
                    | RenameStage::InventoryUpdated
            ) {
                let mut sidecar =
                    FsProfileStore::read_sidecar(&store.sidecar_path("work")).unwrap();
                sidecar.display_name = "work".to_string();
                sidecar.config_file = Some("work.conf".to_string());
                FsProfileStore::write_sidecar(&store.sidecar_path("work"), &sidecar).unwrap();
            }
            if matches!(
                stage,
                RenameStage::AuthMoved
                    | RenameStage::MetadataUpdated
                    | RenameStage::InventoryUpdated
            ) {
                move_once(&old_auth, &store.auth_path(&stable_id)).unwrap();
            }
            if stage == RenameStage::InventoryUpdated {
                crate::vortix_config::migration::rename_inventory_entry(
                    &store.profiles_dir,
                    &stable_id,
                    "work",
                    "work.conf",
                )
                .unwrap();
            }
            intent.stage = stage;
            store.save_intent(&intent).unwrap();

            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            let profile = store.get(&stable_id).unwrap();
            assert_eq!(profile.display_name, "work", "failed at {stage:?}");
            assert_eq!(profile.id, stable_id);
            assert_eq!(store.list().unwrap().len(), 1);
            assert!(!store.intent_path().exists());
        }
    }

    #[test]
    fn insert_recovers_from_every_boundary() {
        for stage in [
            InsertStage::Prepared,
            InsertStage::ConfigWritten,
            InsertStage::SidecarWritten,
            InsertStage::InventoryUpdated,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let store = FsProfileStore::new(tmp.path().join("profiles"));
            std::fs::create_dir_all(&store.profiles_dir).unwrap();
            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            let config = store.config_path("corp", ProtocolKind::WireGuard);
            if stage == InsertStage::Prepared {
                write_atomic(&store.insert_staging_path(), b"[Interface]\n").unwrap();
            } else {
                write_atomic(&config, b"[Interface]\n").unwrap();
            }
            if matches!(
                stage,
                InsertStage::SidecarWritten | InsertStage::InventoryUpdated
            ) {
                let mut sidecar = Sidecar::for_profile(&corp());
                sidecar.config_file = Some("corp.conf".to_string());
                FsProfileStore::write_sidecar(&store.sidecar_path("corp"), &sidecar).unwrap();
            }
            let intent = InsertIntent {
                profile_id: id(1),
                display_name: "corp".to_string(),
                protocol: ProtocolKind::WireGuard,
                config_file: "corp.conf".to_string(),
                stage,
            };
            if stage == InsertStage::InventoryUpdated {
                let profile = Profile::new(id(1), "corp", ProtocolKind::WireGuard, config.clone());
                crate::vortix_config::migration::insert_inventory_entry(
                    &store.profiles_dir,
                    &profile,
                )
                .unwrap();
            }
            store.save_insert_intent(&intent).unwrap();

            store.recover_pending_transactions().unwrap();
            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            assert_eq!(store.get(&id(1)).unwrap().display_name, "corp");
            assert!(!store.insert_intent_path().exists());
            assert!(!store.insert_staging_path().exists());
        }
    }

    #[test]
    fn delete_recovers_from_every_boundary() {
        for stage in [
            DeleteStage::Prepared,
            DeleteStage::ConfigDeleted,
            DeleteStage::SidecarDeleted,
            DeleteStage::AuthDeleted,
            DeleteStage::MetadataUpdated,
            DeleteStage::InventoryUpdated,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let store = FsProfileStore::new(tmp.path().join("profiles"));
            std::fs::create_dir_all(&store.profiles_dir).unwrap();
            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            store.insert(&corp(), b"[Interface]\n").unwrap();
            let config = store.config_path("corp", ProtocolKind::WireGuard);
            let sidecar = store.sidecar_path("corp");
            let auth = store.auth_path(&id(1));
            std::fs::create_dir_all(auth.parent().unwrap()).unwrap();
            std::fs::write(&auth, b"secret").unwrap();
            let metadata = store.root_dir().join("metadata.json");
            std::fs::write(
                &metadata,
                format!("{{\"{}\":{{\"last_used\":null}}}}", config.display()),
            )
            .unwrap();
            if stage != DeleteStage::Prepared {
                remove_if_exists(&config).unwrap();
            }
            if matches!(
                stage,
                DeleteStage::SidecarDeleted
                    | DeleteStage::AuthDeleted
                    | DeleteStage::MetadataUpdated
                    | DeleteStage::InventoryUpdated
            ) {
                remove_if_exists(&sidecar).unwrap();
            }
            if matches!(
                stage,
                DeleteStage::AuthDeleted
                    | DeleteStage::MetadataUpdated
                    | DeleteStage::InventoryUpdated
            ) {
                remove_if_exists(&auth).unwrap();
            }
            if matches!(
                stage,
                DeleteStage::MetadataUpdated | DeleteStage::InventoryUpdated
            ) {
                remove_metadata_key(&metadata, &config).unwrap();
            }
            let intent = DeleteIntent {
                profile_id: id(1),
                display_name: "corp".to_string(),
                protocol: ProtocolKind::WireGuard,
                config_file: "corp.conf".to_string(),
                stage,
            };
            if stage == DeleteStage::InventoryUpdated {
                crate::vortix_config::migration::delete_inventory_entry(
                    &store.profiles_dir,
                    &id(1),
                )
                .unwrap();
            }
            store.save_delete_intent(&intent).unwrap();

            store.recover_pending_transactions().unwrap();
            crate::vortix_config::migration::migrate_legacy_profiles(&store.profiles_dir).unwrap();
            assert!(matches!(
                store.get(&id(1)),
                Err(ProfileStoreError::NotFound(_))
            ));
            assert!(!auth.exists());
            assert!(!std::fs::read_to_string(&metadata)
                .unwrap()
                .contains("corp.conf"));
            assert!(!store.delete_intent_path().exists());
        }
    }

    #[test]
    fn tampered_rename_paths_are_rejected_without_external_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        let outside = tmp.path().join("outside.conf");
        std::fs::write(&outside, b"keep").unwrap();
        let body = format!(
            "profile_id = \"{}\"\nold_name = \"corp\"\nnew_name = \"work\"\nprotocol = \"WireGuard\"\nold_config_file = \"{}\"\nnew_config_file = \"work.conf\"\nstage = \"Prepared\"\n",
            id(1),
            outside.display()
        );
        std::fs::write(store.intent_path(), body).unwrap();
        assert!(store.recover_pending_transactions().is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(store.config_path("corp", ProtocolKind::WireGuard).exists());
    }

    #[test]
    fn touch_recovers_pending_rename_without_relocking_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        let intent = RenameIntent {
            profile_id: id(1),
            old_name: "corp".to_string(),
            new_name: "work".to_string(),
            protocol: ProtocolKind::WireGuard,
            old_config_file: "corp.conf".to_string(),
            new_config_file: "work.conf".to_string(),
            stage: RenameStage::Prepared,
        };
        store.save_intent(&intent).unwrap();
        store.touch(&id(1)).unwrap();
        assert_eq!(store.get(&id(1)).unwrap().display_name, "work");
    }

    #[test]
    fn delete_recovers_pending_rename_without_relocking_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsProfileStore::new(tmp.path().join("profiles"));
        store.insert(&corp(), b"[Interface]\n").unwrap();
        let intent = RenameIntent {
            profile_id: id(1),
            old_name: "corp".to_string(),
            new_name: "work".to_string(),
            protocol: ProtocolKind::WireGuard,
            old_config_file: "corp.conf".to_string(),
            new_config_file: "work.conf".to_string(),
            stage: RenameStage::Prepared,
        };
        store.save_intent(&intent).unwrap();
        store.delete(&id(1)).unwrap();
        assert!(matches!(
            store.get(&id(1)),
            Err(ProfileStoreError::NotFound(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_profile_root_is_rejected_before_creation() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let linked_root = tmp.path().join("linked");
        symlink(&outside, &linked_root).unwrap();
        let store = FsProfileStore::new(linked_root.join("profiles"));
        assert!(store.insert(&corp(), b"secret").is_err());
        assert!(!outside.join("profiles").exists());
    }

    #[cfg(unix)]
    #[test]
    fn lock_contention_returns_typed_busy_error() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = tmp.path().join("profiles");
        let _first = acquire_profile_lock(&profiles).unwrap();
        assert!(matches!(
            acquire_profile_lock(&profiles),
            Err(ProfileStoreError::LockBusy { .. })
        ));
    }
}
