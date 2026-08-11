//! Crash-safe profile sidecar backfill.
//!
//! Migration first persists a complete inventory and the IDs assigned to all
//! legacy configs. Only then does it create sidecars. A crash can therefore
//! resume without deriving a second identity from a name or path.

use std::collections::HashSet;
use std::io::Read as _;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::vortix_config::profile_store::{
    acquire_profile_lock, write_atomic, FsProfileStore, Sidecar,
};
use crate::vortix_core::profile::{sanitize_profile_name, ProfileId, ProtocolKind};

const INVENTORY_FILE: &str = ".vortix-profile-inventory-v1.toml";
const LEGACY_SIDECAR_ARCHIVE_DIR: &str = ".vortix-legacy-sidecars-v1";
const MAX_LEGACY_SIDECAR_BYTES: u64 = 1024 * 1024;

pub(crate) fn rename_inventory_entry(
    profiles_dir: &Path,
    id: &ProfileId,
    new_name: &str,
    config_file: &str,
) -> std::io::Result<()> {
    let path = profiles_dir.join(INVENTORY_FILE);
    if !path.exists() {
        return Ok(());
    }
    let mut inventory = read_inventory(&path)?;
    let entry = inventory
        .entries
        .iter_mut()
        .find(|entry| &entry.profile_id == id)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("profile {id} missing from migration inventory"),
            )
        })?;
    entry.display_name = new_name.to_string();
    entry.config_file = config_file.to_string();
    entry.sidecar_file = format!("{new_name}.meta.toml");
    entry.auth_file = format!("{}.auth", id.as_str());
    validate_inventory_entry(entry)?;
    let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
    write_atomic(&path, body.as_bytes())
}

pub(crate) fn insert_inventory_entry(
    profiles_dir: &Path,
    profile: &crate::vortix_core::profile::Profile,
) -> std::io::Result<()> {
    let path = profiles_dir.join(INVENTORY_FILE);
    if !path.exists() {
        return Ok(());
    }
    let mut inventory = read_inventory(&path)?;
    if let Some(entry) = inventory
        .entries
        .iter()
        .find(|entry| entry.profile_id == profile.id || entry.display_name == profile.display_name)
    {
        if entry.profile_id == profile.id
            && entry.display_name == profile.display_name
            && entry.config_file
                == profile
                    .config_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
        {
            return Ok(());
        }
        return Err(invalid_data(format!(
            "profile inventory collision for {} ({})",
            profile.display_name, profile.id
        )));
    }
    let config_file = profile
        .config_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| invalid_data("profile config has no UTF-8 basename"))?
        .to_string();
    validate_config_name(&config_file, &profile.display_name)?;
    let auth_file = format!("{}.auth", profile.id.as_str());
    let root = profiles_dir.parent().unwrap_or(profiles_dir);
    inventory.entries.push(InventoryEntry {
        config_file,
        sidecar_file: format!("{}.meta.toml", profile.display_name),
        profile_id: profile.id.clone(),
        display_name: profile.display_name.clone(),
        protocol: profile.protocol,
        auth_associated: root.join("auth").join(&auth_file).exists(),
        auth_file,
        boot_associated: root.join("boot.toml").exists(),
        desired_state_associated: root.join("desired-state.toml").exists(),
        had_sidecar: true,
    });
    inventory
        .entries
        .sort_by(|left, right| left.config_file.cmp(&right.config_file));
    let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
    write_atomic(&path, body.as_bytes())
}

pub(crate) fn delete_inventory_entry(profiles_dir: &Path, id: &ProfileId) -> std::io::Result<()> {
    let path = profiles_dir.join(INVENTORY_FILE);
    if !path.exists() {
        return Ok(());
    }
    let mut inventory = read_inventory(&path)?;
    inventory.entries.retain(|entry| &entry.profile_id != id);
    let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
    write_atomic(&path, body.as_bytes())
}

#[derive(Debug, Default, Clone)]
pub struct MigrationStats {
    pub already_migrated: u32,
    pub created: u32,
    pub failed: u32,
    pub ignored: u32,
    pub archived_legacy_sidecars: u32,
}

/// Durable pre-mutation record used for resume and rollback inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInventory {
    pub schema_version: u32,
    pub entries: Vec<InventoryEntry>,
    #[serde(default)]
    pub legacy_sidecar_archive_completed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_sidecars_pending_archive: Vec<LegacySidecarArchiveEntry>,
}

/// One byte-authenticated legacy sidecar scheduled for archival.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySidecarArchiveEntry {
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

/// One config and every identity-bearing association known at migration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // explicit inventory facts must remain independently rollback-readable
#[serde(deny_unknown_fields)]
pub struct InventoryEntry {
    pub config_file: String,
    pub sidecar_file: String,
    pub profile_id: ProfileId,
    pub display_name: String,
    pub protocol: ProtocolKind,
    pub auth_file: String,
    pub auth_associated: bool,
    pub boot_associated: bool,
    pub desired_state_associated: bool,
    pub had_sidecar: bool,
}

/// Backfill missing sidecars using an inventory saved before the first write.
///
/// Any malformed/duplicate identity or unexplained config-set change aborts
/// the whole migration. Callers must not start lifecycle mutation after this
/// function fails.
pub fn migrate_legacy_profiles(profiles_dir: &Path) -> std::io::Result<MigrationStats> {
    if !profiles_dir.exists() {
        return Ok(MigrationStats::default());
    }
    let store = FsProfileStore::new(profiles_dir.to_path_buf());
    let lock = acquire_profile_lock(profiles_dir).map_err(store_error)?;
    store
        .recover_pending_transactions_guarded(&lock)
        .map_err(store_error)?;
    let inventory_path = profiles_dir.join(INVENTORY_FILE);
    let mut inventory = if inventory_path.exists() {
        read_inventory(&inventory_path)?
    } else {
        let (mut inventory, legacy_orphans) = build_initial_inventory(profiles_dir)?;
        inventory.legacy_sidecars_pending_archive = legacy_orphans;
        inventory.legacy_sidecar_archive_completed =
            inventory.legacy_sidecars_pending_archive.is_empty();
        let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
        write_atomic(&inventory_path, body.as_bytes())?;
        inventory
    };

    // Inventories written before the archive phase existed deserialize with
    // `completed = false`. Discover their legacy sidecars once, validate the
    // saved active catalog, and persist the exact bytes before any mutation.
    if !inventory.legacy_sidecar_archive_completed
        && inventory.legacy_sidecars_pending_archive.is_empty()
    {
        inventory.legacy_sidecars_pending_archive =
            discover_legacy_sidecars(profiles_dir, &inventory)?;
        inventory.legacy_sidecar_archive_completed =
            inventory.legacy_sidecars_pending_archive.is_empty();
        let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
        write_atomic(&inventory_path, body.as_bytes())?;
    }

    let archived_legacy_sidecars =
        u32::try_from(inventory.legacy_sidecars_pending_archive.len()).unwrap_or(u32::MAX);
    if archived_legacy_sidecars > 0 {
        validate_pending_archive(profiles_dir, &inventory)?;
        archive_legacy_sidecars(profiles_dir, &inventory.legacy_sidecars_pending_archive)?;
        inventory.legacy_sidecars_pending_archive.clear();
        inventory.legacy_sidecar_archive_completed = true;
        let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
        write_atomic(&inventory_path, body.as_bytes())?;
    }

    validate_inventory(profiles_dir, &inventory)?;
    let mut stats = MigrationStats {
        ignored: count_ignored_files(profiles_dir)?,
        archived_legacy_sidecars,
        ..MigrationStats::default()
    };
    for entry in &inventory.entries {
        validate_inventory_entry(entry)?;
        let sidecar_path = profiles_dir.join(&entry.sidecar_file);
        if sidecar_path.exists() {
            stats.already_migrated = stats.already_migrated.saturating_add(1);
            continue;
        }
        let config_path = profiles_dir.join(&entry.config_file);
        let imported_at = std::fs::metadata(&config_path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .or(Some(SystemTime::now()));
        let sidecar = Sidecar {
            schema_version: Sidecar::SCHEMA_VERSION,
            profile_id: entry.profile_id.as_str().to_string(),
            display_name: entry.display_name.clone(),
            protocol: entry.protocol,
            config_file: Some(entry.config_file.clone()),
            group: None,
            source: Some("migration:v2-inventory".to_string()),
            imported_at,
            last_used: None,
        };
        FsProfileStore::write_sidecar(&sidecar_path, &sidecar).map_err(store_error)?;
        stats.created = stats.created.saturating_add(1);
    }
    validate_inventory(profiles_dir, &inventory)?;
    Ok(stats)
}

fn count_ignored_files(profiles_dir: &Path) -> std::io::Result<u32> {
    let mut ignored = 0_u32;
    for entry in std::fs::read_dir(profiles_dir)? {
        let path = entry?.path();
        reject_symlink_path(&path)?;
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let internal = name == INVENTORY_FILE
            || name == ".vortix-profile.lock"
            || name == ".vortix-profile-rename.toml"
            || name == ".vortix-profile-insert.toml"
            || name == ".vortix-profile-insert.config"
            || name == ".vortix-profile-delete.toml"
            || name.ends_with(".meta.toml");
        let config = matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("conf" | "ovpn")
        );
        if !internal && !config {
            ignored = ignored.saturating_add(1);
        }
    }
    Ok(ignored)
}

#[allow(clippy::too_many_lines)] // one pre-mutation pass records every identity-bearing association together
fn build_initial_inventory(
    profiles_dir: &Path,
) -> std::io::Result<(MigrationInventory, Vec<LegacySidecarArchiveEntry>)> {
    let mut configs = Vec::new();
    let mut sidecar_names = HashSet::new();
    for entry in std::fs::read_dir(profiles_dir)? {
        let path = entry?.path();
        reject_symlink_path(&path)?;
        if !path.is_file() {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-UTF-8 profile filename",
                )
            })?;
        if file_name.ends_with(".meta.toml") {
            sidecar_names.insert(file_name.to_string());
            continue;
        }
        let protocol = match path.extension().and_then(|extension| extension.to_str()) {
            Some("conf") => detect_conf_protocol(&path)?,
            Some("ovpn") => ProtocolKind::OpenVpn,
            _ => {
                continue;
            }
        };
        let display_name = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 profile name")
            })?
            .to_string();
        configs.push((file_name.to_string(), display_name, protocol));
    }
    configs.sort_by(|left, right| left.0.cmp(&right.0));
    let root = profiles_dir.parent().unwrap_or(profiles_dir);
    let mut ids = HashSet::new();
    let mut target_sidecars = HashSet::new();
    let mut associated_auth = HashSet::new();
    let mut entries = Vec::with_capacity(configs.len());
    for (config_file, display_name, protocol) in configs {
        let sidecar_file = format!("{display_name}.meta.toml");
        if !target_sidecars.insert(sidecar_file.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "multiple configs map to sidecar {sidecar_file}; rename one profile before migration"
                ),
            ));
        }
        let sidecar_path = profiles_dir.join(&sidecar_file);
        let had_sidecar = sidecar_path.exists();
        let profile_id = if had_sidecar {
            let sidecar = FsProfileStore::read_sidecar(&sidecar_path).map_err(store_error)?;
            if sidecar.display_name != display_name
                || sidecar
                    .config_file
                    .as_deref()
                    .is_some_and(|file| file != config_file)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} does not describe {}",
                        sidecar_path.display(),
                        config_file
                    ),
                ));
            }
            if sidecar.protocol != protocol {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} protocol does not match config content",
                        sidecar_path.display()
                    ),
                ));
            }
            ProfileId::parse(sidecar.profile_id).map_err(invalid_data)?
        } else {
            ProfileId::generate()?
        };
        if !ids.insert(profile_id.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("duplicate profile ID {profile_id}"),
            ));
        }
        sidecar_names.remove(&sidecar_file);
        let auth_file = format!("{}.auth", profile_id.as_str());
        let legacy_auth = sanitize_profile_name(&display_name);
        let auth_associated = root.join("auth").join(&auth_file).exists()
            || (legacy_auth == display_name
                && root
                    .join("auth")
                    .join(format!("{legacy_auth}.auth"))
                    .exists());
        if !associated_auth.insert(auth_file.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("multiple profiles share auth association {auth_file}"),
            ));
        }
        entries.push(InventoryEntry {
            config_file,
            sidecar_file,
            profile_id,
            display_name,
            protocol,
            auth_associated,
            auth_file,
            // These schemas are stable-ID keyed. Presence is inventoried so
            // migration/rename recovery can prove no association disappeared.
            boot_associated: root.join("boot.toml").exists(),
            desired_state_associated: root.join("desired-state.toml").exists(),
            had_sidecar,
        });
    }
    // A sidecar without a config cannot authorize lifecycle work. Preserve it
    // opaquely rather than trusting or deleting metadata written by an older
    // release.
    let mut legacy_orphans = sidecar_names
        .into_iter()
        .map(|name| legacy_archive_entry(&profiles_dir.join(&name), name))
        .collect::<std::io::Result<Vec<_>>>()?;
    legacy_orphans.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    Ok((
        MigrationInventory {
            schema_version: 1,
            entries,
            legacy_sidecar_archive_completed: false,
            legacy_sidecars_pending_archive: Vec::new(),
        },
        legacy_orphans,
    ))
}

fn legacy_archive_entry(
    path: &Path,
    file_name: String,
) -> std::io::Result<LegacySidecarArchiveEntry> {
    let file = open_legacy_sidecar(path)?;
    legacy_archive_entry_from_file(&file, file_name)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_legacy_sidecar(path: &Path) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("legacy sidecar has no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid_data("legacy sidecar has no filename"))?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let name = CString::new(name.as_encoded_bytes()).map_err(invalid_data)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn open_legacy_sidecar(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

fn legacy_archive_entry_from_file(
    file: &std::fs::File,
    file_name: String,
) -> std::io::Result<LegacySidecarArchiveEntry> {
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_data(format!(
            "legacy sidecar is not a safe regular file: {file_name}"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(invalid_data(format!(
                "legacy sidecar {file_name} has an unsafe hard-link count"
            )));
        }
    }
    if metadata.len() > MAX_LEGACY_SIDECAR_BYTES {
        return Err(invalid_data(format!(
            "legacy sidecar exceeds {MAX_LEGACY_SIDECAR_BYTES} bytes: {file_name}"
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.try_clone()?
        .take(MAX_LEGACY_SIDECAR_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(invalid_data(format!(
            "legacy sidecar changed while it was inventoried: {file_name}"
        )));
    }
    Ok(LegacySidecarArchiveEntry {
        file_name,
        size_bytes: metadata.len(),
        sha256: sha256_hex(&bytes),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

fn archive_legacy_sidecars(
    profiles_dir: &Path,
    entries: &[LegacySidecarArchiveEntry],
) -> std::io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    archive_legacy_sidecars_platform(profiles_dir, entries)
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn archive_legacy_sidecars_platform(
    profiles_dir: &Path,
    entries: &[LegacySidecarArchiveEntry],
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let profiles = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(profiles_dir)?;
    let archive_name = CString::new(LEGACY_SIDECAR_ARCHIVE_DIR).expect("static archive name");
    let created =
        if unsafe { libc::mkdirat(profiles.as_raw_fd(), archive_name.as_ptr(), 0o700) } == 0 {
            true
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(error);
            }
            false
        };
    let archive_fd = unsafe {
        libc::openat(
            profiles.as_raw_fd(),
            archive_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if archive_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let archive = unsafe { std::fs::File::from_raw_fd(archive_fd) };
    if unsafe { libc::fchmod(archive.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    chown_open_file_to_invoking_user(&archive)?;
    if created {
        // The archive name must be durable before any source name is removed.
        profiles.sync_all()?;
    }

    for entry in entries {
        validate_legacy_archive_entry(entry)?;
        let name = CString::new(entry.file_name.as_bytes()).map_err(invalid_data)?;
        let source = openat_verified_regular(&profiles, &name, entry)?;
        if let Some(source) = source {
            let existing_archive = openat_verified_regular(&archive, &name, entry)?;
            if existing_archive.is_none() {
                require_link_count(&source, 1, entry)?;
                if unsafe {
                    libc::linkat(
                        profiles.as_raw_fd(),
                        name.as_ptr(),
                        archive.as_raw_fd(),
                        name.as_ptr(),
                        0,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let archived = openat_verified_regular(&archive, &name, entry)?.ok_or_else(|| {
                invalid_data(format!(
                    "legacy sidecar archive lost {} before commit",
                    entry.file_name
                ))
            })?;
            require_same_file(&source, &archived, entry)?;
            require_link_count(&archived, 2, entry)?;
            chown_open_file_to_invoking_user(&archived)?;
            archived.sync_all()?;
            archive.sync_all()?;

            // Re-open the current source name after linking. Never unlink a
            // replacement that no longer matches the durable record.
            openat_verified_regular(&profiles, &name, entry)?.ok_or_else(|| {
                invalid_data(format!(
                    "legacy sidecar {} changed during archival",
                    entry.file_name
                ))
            })?;
            verify_open_directory_name(&profiles, &archive_name, &archive)?;
            if unsafe { libc::unlinkat(profiles.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            profiles.sync_all()?;
        } else {
            let archived = openat_verified_regular(&archive, &name, entry)?.ok_or_else(|| {
                invalid_data(format!(
                    "legacy sidecar {} is missing from both active and archive storage; restore it before restarting Vortix",
                    entry.file_name
                ))
            })?;
            require_link_count(&archived, 1, entry)?;
            chown_open_file_to_invoking_user(&archived)?;
            archived.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_same_file(
    left: &std::fs::File,
    right: &std::fs::File,
    entry: &LegacySidecarArchiveEntry,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let left = left.metadata()?;
    let right = right.metadata()?;
    if left.dev() != right.dev() || left.ino() != right.ino() {
        return Err(invalid_data(format!(
            "legacy sidecar archive already contains a different file for {}",
            entry.file_name
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn require_link_count(
    file: &std::fs::File,
    expected: u64,
    entry: &LegacySidecarArchiveEntry,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if file.metadata()?.nlink() != expected {
        return Err(invalid_data(format!(
            "legacy sidecar {} has an unsafe hard-link count",
            entry.file_name
        )));
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn verify_open_directory_name(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    directory: &std::fs::File,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let mut opened = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut current = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(directory.as_raw_fd(), opened.as_mut_ptr()) } != 0
        || unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                current.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let opened = unsafe { opened.assume_init() };
    let current = unsafe { current.assume_init() };
    if opened.st_dev != current.st_dev || opened.st_ino != current.st_ino {
        return Err(invalid_data(
            "legacy sidecar archive directory changed during migration",
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn openat_verified_regular(
    directory: &std::fs::File,
    name: &std::ffi::CStr,
    expected: &LegacySidecarArchiveEntry,
) -> std::io::Result<Option<std::fs::File>> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    verify_archive_file(&file, expected)?;
    Ok(Some(file))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn chown_open_file_to_invoking_user(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if !crate::utils::is_root() {
        return Ok(());
    }
    let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) else {
        return Ok(());
    };
    let uid = uid
        .parse::<libc::uid_t>()
        .map_err(|error| invalid_data(format!("invalid SUDO_UID: {error}")))?;
    let gid = gid
        .parse::<libc::gid_t>()
        .map_err(|error| invalid_data(format!("invalid SUDO_GID: {error}")))?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn archive_legacy_sidecars_platform(
    profiles_dir: &Path,
    entries: &[LegacySidecarArchiveEntry],
) -> std::io::Result<()> {
    let archive = profiles_dir.join(LEGACY_SIDECAR_ARCHIVE_DIR);
    std::fs::create_dir(&archive).or_else(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(error)
        }
    })?;
    for entry in entries {
        validate_legacy_archive_entry(entry)?;
        let source = profiles_dir.join(&entry.file_name);
        let destination = archive.join(&entry.file_name);
        if source.exists() {
            verify_archive_file(&std::fs::File::open(&source)?, entry)?;
            match std::fs::hard_link(&source, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    verify_archive_file(&std::fs::File::open(&destination)?, entry)?;
                }
                Err(error) => return Err(error),
            }
            std::fs::remove_file(source)?;
        } else {
            verify_archive_file(&std::fs::File::open(destination)?, entry)?;
        }
    }
    Ok(())
}

fn verify_archive_file(
    file: &std::fs::File,
    expected: &LegacySidecarArchiveEntry,
) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() != expected.size_bytes
        || metadata.len() > MAX_LEGACY_SIDECAR_BYTES
    {
        return Err(invalid_data(format!(
            "legacy sidecar {} does not match its durable archive record",
            expected.file_name
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.try_clone()?
        .take(MAX_LEGACY_SIDECAR_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != expected.size_bytes
        || sha256_hex(&bytes) != expected.sha256
    {
        return Err(invalid_data(format!(
            "legacy sidecar {} does not match its durable archive record",
            expected.file_name
        )));
    }
    Ok(())
}

fn validate_legacy_archive_entry(entry: &LegacySidecarArchiveEntry) -> std::io::Result<()> {
    validate_exact_basename(&entry.file_name, &entry.file_name)?;
    if !entry.file_name.ends_with(".meta.toml")
        || entry.size_bytes > MAX_LEGACY_SIDECAR_BYTES
        || entry.sha256.len() != 64
        || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid_data(format!(
            "unsafe legacy sidecar archive record {}",
            entry.file_name
        )));
    }
    Ok(())
}

fn read_inventory(path: &Path) -> std::io::Result<MigrationInventory> {
    let text = std::fs::read_to_string(path)?;
    let inventory: MigrationInventory = toml::from_str(&text).map_err(invalid_data)?;
    if inventory.schema_version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported profile inventory schema",
        ));
    }
    for entry in &inventory.entries {
        validate_inventory_entry(entry)?;
    }
    let mut pending_names = HashSet::new();
    for entry in &inventory.legacy_sidecars_pending_archive {
        validate_legacy_archive_entry(entry)?;
        if !pending_names.insert(entry.file_name.as_str()) {
            return Err(invalid_data(format!(
                "duplicate legacy sidecar archive record {}",
                entry.file_name
            )));
        }
    }
    Ok(inventory)
}

fn discover_legacy_sidecars(
    profiles_dir: &Path,
    inventory: &MigrationInventory,
) -> std::io::Result<Vec<LegacySidecarArchiveEntry>> {
    let (configs, sidecars) = scan_profile_files(profiles_dir)?;
    validate_saved_configs_and_sidecars(profiles_dir, inventory, &configs)?;
    let active = inventory
        .entries
        .iter()
        .map(|entry| entry.sidecar_file.as_str())
        .collect::<HashSet<_>>();
    let mut legacy = sidecars
        .into_iter()
        .filter(|name| !active.contains(name.as_str()))
        .map(|name| legacy_archive_entry(&profiles_dir.join(&name), name))
        .collect::<std::io::Result<Vec<_>>>()?;
    legacy.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    Ok(legacy)
}

fn validate_pending_archive(
    profiles_dir: &Path,
    inventory: &MigrationInventory,
) -> std::io::Result<()> {
    let (configs, sidecars) = scan_profile_files(profiles_dir)?;
    validate_saved_configs_and_sidecars(profiles_dir, inventory, &configs)?;
    let active = inventory
        .entries
        .iter()
        .map(|entry| entry.sidecar_file.as_str())
        .collect::<HashSet<_>>();
    let pending = inventory
        .legacy_sidecars_pending_archive
        .iter()
        .map(|entry| entry.file_name.as_str())
        .collect::<HashSet<_>>();
    if pending.iter().any(|name| active.contains(name)) {
        return Err(invalid_data(
            "legacy sidecar archive record collides with an active profile",
        ));
    }
    if let Some(unexplained) = sidecars
        .iter()
        .find(|name| !active.contains(name.as_str()) && !pending.contains(name.as_str()))
    {
        return Err(invalid_data(format!(
            "unexplained sidecar {unexplained} appeared during migration"
        )));
    }
    let archive = profiles_dir.join(LEGACY_SIDECAR_ARCHIVE_DIR);
    for entry in &inventory.legacy_sidecars_pending_archive {
        let source = profiles_dir.join(&entry.file_name);
        let destination = archive.join(&entry.file_name);
        match (
            verified_path_if_present(&source, entry)?,
            verified_path_if_present(&destination, entry)?,
        ) {
            (true, _) | (false, true) => {}
            (false, false) => {
                return Err(invalid_data(format!(
                    "legacy sidecar {} is missing from both active and archive storage; restore it before restarting Vortix",
                    entry.file_name
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verified_path_if_present(
    path: &Path,
    expected: &LegacySidecarArchiveEntry,
) -> std::io::Result<bool> {
    match open_legacy_sidecar(path) {
        Ok(file) => {
            verify_archive_file(&file, expected)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn verified_path_if_present(
    path: &Path,
    expected: &LegacySidecarArchiveEntry,
) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(invalid_data(format!(
                "legacy sidecar is not a safe regular file: {}",
                path.display()
            )))
        }
        Ok(_) => {
            verify_archive_file(&std::fs::File::open(path)?, expected)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn scan_profile_files(profiles_dir: &Path) -> std::io::Result<(HashSet<String>, HashSet<String>)> {
    let mut configs = HashSet::new();
    let mut sidecars = HashSet::new();
    for entry in std::fs::read_dir(profiles_dir)? {
        let path = entry?.path();
        reject_symlink_path(&path)?;
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("conf" | "ovpn")
        ) {
            configs.insert(file_name.to_string());
        }
        if file_name.ends_with(".meta.toml") {
            sidecars.insert(file_name.to_string());
        }
    }
    Ok((configs, sidecars))
}

fn validate_saved_configs_and_sidecars(
    profiles_dir: &Path,
    inventory: &MigrationInventory,
    current_configs: &HashSet<String>,
) -> std::io::Result<()> {
    let expected_configs = inventory
        .entries
        .iter()
        .map(|entry| entry.config_file.clone())
        .collect::<HashSet<_>>();
    if current_configs != &expected_configs {
        return Err(invalid_data(
            "profile config inventory changed during migration",
        ));
    }
    let mut ids = HashSet::new();
    for entry in &inventory.entries {
        validate_inventory_entry(entry)?;
        if !ids.insert(entry.profile_id.clone()) {
            return Err(invalid_data(format!(
                "duplicate inventory profile ID {}",
                entry.profile_id
            )));
        }
        let sidecar_path = profiles_dir.join(&entry.sidecar_file);
        if sidecar_path.exists() {
            let sidecar = FsProfileStore::read_sidecar(&sidecar_path).map_err(store_error)?;
            if sidecar.profile_id != entry.profile_id.as_str()
                || sidecar.display_name != entry.display_name
                || sidecar.protocol != entry.protocol
                || sidecar
                    .config_file
                    .as_deref()
                    .is_some_and(|file| file != entry.config_file)
            {
                return Err(invalid_data(format!(
                    "{} diverged from saved inventory",
                    sidecar_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_inventory(profiles_dir: &Path, inventory: &MigrationInventory) -> std::io::Result<()> {
    if !inventory.legacy_sidecar_archive_completed
        || !inventory.legacy_sidecars_pending_archive.is_empty()
    {
        return Err(invalid_data("legacy sidecar archival is still pending"));
    }
    let (configs, sidecars) = scan_profile_files(profiles_dir)?;
    validate_saved_configs_and_sidecars(profiles_dir, inventory, &configs)?;
    let active_sidecars = inventory
        .entries
        .iter()
        .map(|entry| entry.sidecar_file.as_str())
        .collect::<HashSet<_>>();
    if let Some(unexplained) = sidecars
        .iter()
        .find(|name| !active_sidecars.contains(name.as_str()))
    {
        return Err(invalid_data(format!("unexplained sidecar {unexplained}")));
    }
    Ok(())
}

fn detect_conf_protocol(path: &Path) -> std::io::Result<ProtocolKind> {
    let body = std::fs::read_to_string(path)?;
    let mut wireguard = false;
    let mut openvpn = false;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if matches!(line, "[Interface]" | "[Peer]") {
            wireguard = true;
        }
        let directive = line.split_whitespace().next().unwrap_or_default();
        if matches!(
            directive,
            "client" | "dev" | "remote" | "proto" | "ca" | "cert" | "key" | "auth-user-pass"
        ) {
            openvpn = true;
        }
    }
    match (wireguard, openvpn) {
        (false, true) => Ok(ProtocolKind::OpenVpn),
        (_, false) => Ok(ProtocolKind::WireGuard),
        (true, true) => Err(invalid_data(format!(
            "ambiguous .conf profile {} contains WireGuard and OpenVPN syntax",
            path.display()
        ))),
    }
}

fn validate_inventory_entry(entry: &InventoryEntry) -> std::io::Result<()> {
    validate_config_name(&entry.config_file, &entry.display_name)?;
    validate_exact_basename(
        &entry.sidecar_file,
        &format!("{}.meta.toml", entry.display_name),
    )?;
    validate_exact_basename(
        &entry.auth_file,
        &format!("{}.auth", entry.profile_id.as_str()),
    )
}

fn validate_config_name(file: &str, display_name: &str) -> std::io::Result<()> {
    let path = Path::new(file);
    if path.is_absolute()
        || path.components().count() != 1
        || path.file_stem().and_then(|value| value.to_str()) != Some(display_name)
        || !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("conf" | "ovpn")
        )
    {
        return Err(invalid_data(format!(
            "unsafe inventory config filename {file}"
        )));
    }
    Ok(())
}

fn validate_exact_basename(file: &str, expected: &str) -> std::io::Result<()> {
    let path = Path::new(file);
    if file != expected || path.is_absolute() || path.components().count() != 1 {
        return Err(invalid_data(format!("unsafe inventory filename {file}")));
    }
    Ok(())
}

fn reject_symlink_path(path: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "refusing symlink in profile storage: {}",
            path.display()
        )));
    }
    Ok(())
}

fn invalid_data(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

fn store_error(error: impl std::fmt::Display) -> std::io::Error {
    invalid_data(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vortix_config::profile_store::ProfileStore as _;

    #[test]
    fn pre_sidecar_migration_is_inventory_first_and_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let first = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(first.created, 1);
        assert!(tmp.path().join(INVENTORY_FILE).exists());
        let first_sidecar =
            FsProfileStore::read_sidecar(&tmp.path().join("corp.meta.toml")).unwrap();
        let second = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(second.already_migrated, 1);
        let second_sidecar =
            FsProfileStore::read_sidecar(&tmp.path().join("corp.meta.toml")).unwrap();
        assert_eq!(first_sidecar.profile_id, second_sidecar.profile_id);
    }

    #[test]
    fn first_canonical_migration_archives_configless_legacy_sidecars() {
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("corp.conf");
        let original = b"[Interface]\nPrivateKey = preserved\n";
        std::fs::write(&config, original).unwrap();

        let preserved_id = "01".repeat(32);
        let active_sidecar = Sidecar {
            schema_version: Sidecar::SCHEMA_VERSION,
            profile_id: preserved_id.clone(),
            display_name: "corp".to_string(),
            protocol: ProtocolKind::WireGuard,
            config_file: None,
            group: None,
            source: Some("migration:v1".to_string()),
            imported_at: None,
            last_used: None,
        };
        FsProfileStore::write_sidecar(&tmp.path().join("corp.meta.toml"), &active_sidecar).unwrap();

        let deleted_sidecar = Sidecar {
            profile_id: "02".repeat(32),
            display_name: "deleted".to_string(),
            ..active_sidecar
        };
        let deleted_path = tmp.path().join("deleted.meta.toml");
        FsProfileStore::write_sidecar(&deleted_path, &deleted_sidecar).unwrap();
        let deleted_bytes = std::fs::read(&deleted_path).unwrap();

        let first = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(first.already_migrated, 1);
        assert_eq!(first.archived_legacy_sidecars, 1);
        assert_eq!(std::fs::read(&config).unwrap(), original);
        assert!(!tmp.path().join("deleted.meta.toml").exists());
        let archived = tmp
            .path()
            .join(LEGACY_SIDECAR_ARCHIVE_DIR)
            .join("deleted.meta.toml");
        assert_eq!(std::fs::read(archived).unwrap(), deleted_bytes);

        let store = FsProfileStore::new(tmp.path().to_path_buf());
        let profiles = store.list().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].display_name, "corp");
        assert_eq!(profiles[0].id.as_str(), preserved_id);

        let second = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(second.already_migrated, 1);
    }

    #[test]
    fn pending_legacy_archive_resumes_without_regenerating_profile_ids() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        std::fs::write(tmp.path().join("deleted-a.meta.toml"), b"first").unwrap();
        std::fs::write(tmp.path().join("deleted-b.meta.toml"), b"second").unwrap();

        let (mut inventory, legacy_orphans) = build_initial_inventory(tmp.path()).unwrap();
        let assigned_id = inventory.entries[0].profile_id.clone();
        inventory.legacy_sidecars_pending_archive = legacy_orphans;
        let body = toml::to_string_pretty(&inventory).unwrap();
        write_atomic(&tmp.path().join(INVENTORY_FILE), body.as_bytes()).unwrap();

        let archive = tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR);
        std::fs::create_dir(&archive).unwrap();
        std::fs::hard_link(
            tmp.path().join("deleted-a.meta.toml"),
            archive.join("deleted-a.meta.toml"),
        )
        .unwrap();
        std::fs::remove_file(tmp.path().join("deleted-a.meta.toml")).unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.archived_legacy_sidecars, 2);
        assert!(archive.join("deleted-a.meta.toml").is_file());
        assert!(archive.join("deleted-b.meta.toml").is_file());
        assert!(!tmp.path().join("deleted-a.meta.toml").exists());

        let final_inventory = read_inventory(&tmp.path().join(INVENTORY_FILE)).unwrap();
        assert!(final_inventory.legacy_sidecar_archive_completed);
        assert!(final_inventory.legacy_sidecars_pending_archive.is_empty());
        assert_eq!(final_inventory.entries[0].profile_id, assigned_id);
    }

    #[test]
    fn restored_config_refuses_before_pending_sidecar_is_archived() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        std::fs::write(tmp.path().join("deleted.meta.toml"), b"legacy").unwrap();
        let (mut inventory, pending) = build_initial_inventory(tmp.path()).unwrap();
        inventory.legacy_sidecars_pending_archive = pending;
        write_atomic(
            &tmp.path().join(INVENTORY_FILE),
            toml::to_string_pretty(&inventory).unwrap().as_bytes(),
        )
        .unwrap();

        std::fs::write(tmp.path().join("deleted.conf"), b"[Interface]\n").unwrap();
        let error = migrate_legacy_profiles(tmp.path()).unwrap_err();
        assert!(error.to_string().contains("config inventory changed"));
        assert_eq!(
            std::fs::read(tmp.path().join("deleted.meta.toml")).unwrap(),
            b"legacy"
        );
        assert!(!tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR).exists());
        assert!(!read_inventory(&tmp.path().join(INVENTORY_FILE))
            .unwrap()
            .legacy_sidecars_pending_archive
            .is_empty());
    }

    #[test]
    fn pending_active_sidecar_collision_refuses_without_metadata_loss() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let active = Sidecar {
            schema_version: Sidecar::SCHEMA_VERSION,
            profile_id: "03".repeat(32),
            display_name: "corp".to_string(),
            protocol: ProtocolKind::WireGuard,
            config_file: Some("corp.conf".to_string()),
            group: Some("work".to_string()),
            source: Some("import".to_string()),
            imported_at: None,
            last_used: Some(SystemTime::now()),
        };
        let path = tmp.path().join("corp.meta.toml");
        FsProfileStore::write_sidecar(&path, &active).unwrap();
        let original = std::fs::read(&path).unwrap();
        let (mut inventory, pending) = build_initial_inventory(tmp.path()).unwrap();
        assert!(pending.is_empty());
        inventory.legacy_sidecars_pending_archive =
            vec![legacy_archive_entry(&path, "corp.meta.toml".to_string()).unwrap()];
        write_atomic(
            &tmp.path().join(INVENTORY_FILE),
            toml::to_string_pretty(&inventory).unwrap().as_bytes(),
        )
        .unwrap();

        let error = migrate_legacy_profiles(tmp.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("collides with an active profile"));
        assert_eq!(std::fs::read(path).unwrap(), original);
        assert!(!tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR).exists());
    }

    #[test]
    fn missing_pending_sidecar_retains_durable_intent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let orphan = tmp.path().join("deleted.meta.toml");
        std::fs::write(&orphan, b"legacy").unwrap();
        let (mut inventory, pending) = build_initial_inventory(tmp.path()).unwrap();
        inventory.legacy_sidecars_pending_archive = pending;
        write_atomic(
            &tmp.path().join(INVENTORY_FILE),
            toml::to_string_pretty(&inventory).unwrap().as_bytes(),
        )
        .unwrap();
        std::fs::remove_file(orphan).unwrap();

        let error = migrate_legacy_profiles(tmp.path()).unwrap_err();
        assert!(error
            .to_string()
            .contains("missing from both active and archive"));
        let saved = read_inventory(&tmp.path().join(INVENTORY_FILE)).unwrap();
        assert!(!saved.legacy_sidecar_archive_completed);
        assert_eq!(saved.legacy_sidecars_pending_archive.len(), 1);
    }

    #[test]
    fn pre_archive_inventory_schema_is_upgraded_once() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        std::fs::write(tmp.path().join("deleted.meta.toml"), b"legacy").unwrap();
        let (inventory, _) = build_initial_inventory(tmp.path()).unwrap();
        let mut old_body = toml::to_string_pretty(&inventory).unwrap();
        old_body = old_body.replace("legacy_sidecar_archive_completed = false\n", "");
        write_atomic(&tmp.path().join(INVENTORY_FILE), old_body.as_bytes()).unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.archived_legacy_sidecars, 1);
        assert_eq!(
            std::fs::read(
                tmp.path()
                    .join(LEGACY_SIDECAR_ARCHIVE_DIR)
                    .join("deleted.meta.toml")
            )
            .unwrap(),
            b"legacy"
        );
        assert!(
            read_inventory(&tmp.path().join(INVENTORY_FILE))
                .unwrap()
                .legacy_sidecar_archive_completed
        );
    }

    #[test]
    fn archive_collision_preserves_both_files_and_pending_intent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let source = tmp.path().join("deleted.meta.toml");
        std::fs::write(&source, b"legacy").unwrap();
        let (mut inventory, pending) = build_initial_inventory(tmp.path()).unwrap();
        inventory.legacy_sidecars_pending_archive = pending;
        write_atomic(
            &tmp.path().join(INVENTORY_FILE),
            toml::to_string_pretty(&inventory).unwrap().as_bytes(),
        )
        .unwrap();
        let archive = tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR);
        std::fs::create_dir(&archive).unwrap();
        std::fs::write(archive.join("deleted.meta.toml"), b"different").unwrap();

        assert!(migrate_legacy_profiles(tmp.path()).is_err());
        assert_eq!(std::fs::read(source).unwrap(), b"legacy");
        assert_eq!(
            std::fs::read(archive.join("deleted.meta.toml")).unwrap(),
            b"different"
        );
        assert_eq!(
            read_inventory(&tmp.path().join(INVENTORY_FILE))
                .unwrap()
                .legacy_sidecars_pending_archive
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_legacy_sidecar_is_rejected_before_inventory_write() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let sidecar = tmp.path().join("deleted.meta.toml");
        let second_link = tmp.path().join("outside-link");
        std::fs::write(&sidecar, b"legacy").unwrap();
        std::fs::hard_link(&sidecar, &second_link).unwrap();

        let error = migrate_legacy_profiles(tmp.path()).unwrap_err();
        assert!(error.to_string().contains("unsafe hard-link count"));
        assert_eq!(std::fs::read(sidecar).unwrap(), b"legacy");
        assert_eq!(std::fs::read(second_link).unwrap(), b"legacy");
        assert!(!tmp.path().join(INVENTORY_FILE).exists());
        assert!(!tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR).exists());
    }

    #[test]
    fn malformed_and_duplicate_sidecars_fail_before_backfill() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"x").unwrap();
        std::fs::write(tmp.path().join("corp.meta.toml"), b"broken = [").unwrap();
        std::fs::write(tmp.path().join("deleted.meta.toml"), b"legacy").unwrap();
        assert!(migrate_legacy_profiles(tmp.path()).is_err());
        assert!(!tmp.path().join(INVENTORY_FILE).exists());
        assert!(tmp.path().join("deleted.meta.toml").exists());
        assert!(!tmp.path().join(LEGACY_SIDECAR_ARCHIVE_DIR).exists());
    }

    #[test]
    fn saved_inventory_resumes_after_sidecar_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.conf"), b"a").unwrap();
        std::fs::write(tmp.path().join("b.ovpn"), b"b").unwrap();
        let (inventory, legacy_orphans) = build_initial_inventory(tmp.path()).unwrap();
        assert!(legacy_orphans.is_empty());
        let body = toml::to_string_pretty(&inventory).unwrap();
        write_atomic(&tmp.path().join(INVENTORY_FILE), body.as_bytes()).unwrap();
        let entry = &inventory.entries[0];
        let partial = Sidecar {
            schema_version: Sidecar::SCHEMA_VERSION,
            profile_id: entry.profile_id.to_string(),
            display_name: entry.display_name.clone(),
            protocol: entry.protocol,
            config_file: Some(entry.config_file.clone()),
            group: None,
            source: Some("migration:v2-inventory".to_string()),
            imported_at: None,
            last_used: None,
        };
        FsProfileStore::write_sidecar(&tmp.path().join(&entry.sidecar_file), &partial).unwrap();
        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 1);
        assert_eq!(stats.already_migrated, 1);
    }

    #[test]
    fn concurrent_migration_assigns_exactly_one_id() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"x").unwrap();
        let dir = std::sync::Arc::new(tmp.path().to_path_buf());
        let workers = (0..2)
            .map(|_| {
                let dir = std::sync::Arc::clone(&dir);
                std::thread::spawn(move || migrate_legacy_profiles(&dir))
            })
            .collect::<Vec<_>>();
        let mut completed = 0;
        for worker in workers {
            match worker.join().unwrap() {
                Ok(_) => completed += 1,
                Err(error)
                    if error.kind() == std::io::ErrorKind::InvalidData
                        && error.to_string().contains("profile storage is busy") => {}
                Err(error) => panic!("concurrent migration failed unexpectedly: {error}"),
            }
        }
        assert!(
            completed >= 1,
            "one concurrent migration must acquire the lock"
        );
        migrate_legacy_profiles(tmp.path()).unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(ProfileId::parse(store.list().unwrap()[0].id.to_string()).is_ok());
    }

    #[test]
    fn conf_protocol_is_detected_from_content_and_persisted() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("corp.conf"),
            b"client\ndev tun\nremote vpn.example 1194\n",
        )
        .unwrap();
        migrate_legacy_profiles(tmp.path()).unwrap();
        let store = FsProfileStore::new(tmp.path().to_path_buf());
        let summary = store.list().unwrap().pop().unwrap();
        assert_eq!(summary.protocol, ProtocolKind::OpenVpn);
        assert_eq!(summary.config_file, "corp.conf");
        assert_eq!(
            store.get(&summary.id).unwrap().config_path,
            tmp.path().join("corp.conf")
        );
    }

    #[test]
    fn tampered_inventory_paths_are_rejected_before_writes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        let outside_name = format!(
            "outside-{}.meta.toml",
            tmp.path().file_name().unwrap().to_string_lossy()
        );
        let outside = tmp.path().parent().unwrap().join(&outside_name);
        let body = format!(
            "schema_version = 1\n\n[[entries]]\nconfig_file = \"corp.conf\"\nsidecar_file = \"../{outside_name}\"\nprofile_id = \"{}\"\ndisplay_name = \"corp\"\nprotocol = \"WireGuard\"\nauth_file = \"{}.auth\"\nauth_associated = false\nboot_associated = false\ndesired_state_associated = false\nhad_sidecar = false\n",
            "01".repeat(32),
            "01".repeat(32)
        );
        std::fs::write(tmp.path().join(INVENTORY_FILE), body).unwrap();
        assert!(migrate_legacy_profiles(tmp.path()).is_err());
        assert!(!outside.exists());
        assert!(!tmp.path().join("corp.meta.toml").exists());
    }
}
