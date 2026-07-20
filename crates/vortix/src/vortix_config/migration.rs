//! Crash-safe profile sidecar backfill.
//!
//! Migration first persists a complete inventory and the IDs assigned to all
//! legacy configs. Only then does it create sidecars. A crash can therefore
//! resume without deriving a second identity from a name or path.

use std::collections::HashSet;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::vortix_config::profile_store::{
    acquire_profile_lock, write_atomic, FsProfileStore, Sidecar,
};
use crate::vortix_core::profile::{sanitize_profile_name, ProfileId, ProtocolKind};

const INVENTORY_FILE: &str = ".vortix-profile-inventory-v1.toml";

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
}

/// Durable pre-mutation record used for resume and rollback inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInventory {
    pub schema_version: u32,
    pub entries: Vec<InventoryEntry>,
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
    let inventory = if inventory_path.exists() {
        read_inventory(&inventory_path)?
    } else {
        let inventory = build_inventory(profiles_dir)?;
        let body = toml::to_string_pretty(&inventory).map_err(invalid_data)?;
        write_atomic(&inventory_path, body.as_bytes())?;
        inventory
    };

    validate_inventory(profiles_dir, &inventory)?;
    let mut stats = MigrationStats {
        ignored: count_ignored_files(profiles_dir)?,
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
fn build_inventory(profiles_dir: &Path) -> std::io::Result<MigrationInventory> {
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
    if let Some(orphan) = sidecar_names.into_iter().next() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sidecar {orphan} has no matching config"),
        ));
    }
    Ok(MigrationInventory {
        schema_version: 1,
        entries,
    })
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
    Ok(inventory)
}

fn validate_inventory(profiles_dir: &Path, inventory: &MigrationInventory) -> std::io::Result<()> {
    let current = build_inventory_for_validation(profiles_dir, inventory)?;
    if current
        != inventory
            .entries
            .iter()
            .map(|entry| entry.config_file.clone())
            .collect::<HashSet<_>>()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "profile config inventory changed during migration",
        ));
    }
    let mut ids = HashSet::new();
    for entry in &inventory.entries {
        validate_inventory_entry(entry)?;
        ProfileId::parse(entry.profile_id.as_str().to_string()).map_err(invalid_data)?;
        if !ids.insert(entry.profile_id.clone()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("duplicate inventory profile ID {}", entry.profile_id),
            ));
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{} diverged from saved inventory", sidecar_path.display()),
                ));
            }
        }
    }
    Ok(())
}

fn build_inventory_for_validation(
    profiles_dir: &Path,
    inventory: &MigrationInventory,
) -> std::io::Result<HashSet<String>> {
    let inventory_file_names = inventory
        .entries
        .iter()
        .map(|entry| entry.sidecar_file.as_str())
        .collect::<HashSet<_>>();
    let mut configs = HashSet::new();
    for entry in std::fs::read_dir(profiles_dir)? {
        let path = entry?.path();
        reject_symlink_path(&path)?;
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some("conf" | "ovpn") = path.extension().and_then(|extension| extension.to_str()) {
            configs.insert(file_name.to_string());
        }
        if file_name.ends_with(".meta.toml") && !inventory_file_names.contains(file_name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexplained sidecar {file_name}"),
            ));
        }
    }
    Ok(configs)
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
    fn malformed_and_duplicate_sidecars_fail_before_backfill() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("corp.conf"), b"x").unwrap();
        std::fs::write(tmp.path().join("corp.meta.toml"), b"broken = [").unwrap();
        assert!(migrate_legacy_profiles(tmp.path()).is_err());
        assert!(!tmp.path().join(INVENTORY_FILE).exists());
    }

    #[test]
    fn saved_inventory_resumes_after_sidecar_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.conf"), b"a").unwrap();
        std::fs::write(tmp.path().join("b.ovpn"), b"b").unwrap();
        let inventory = build_inventory(tmp.path()).unwrap();
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
                std::thread::spawn(move || migrate_legacy_profiles(&dir).unwrap())
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
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
