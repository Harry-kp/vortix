//! One-shot profile sidecar backfill (plan #006 U4).
//!
//! Idempotent migration that walks the profiles directory, detects bare
//! `.conf` / `.ovpn` files without a sibling `.meta.toml`, and writes a
//! sidecar carrying:
//! - `profile_id` = SHA-256(display_name + first 4 KiB of body), hex.
//! - `display_name` = filename stem.
//! - `protocol` = `WireGuard` (.conf) or `OpenVpn` (.ovpn).
//! - `imported_at` = file mtime.
//!
//! Behaviour intentionally conservative:
//! - Never modifies or deletes existing `.conf` / `.ovpn` files.
//! - Skips files that already have a sidecar (idempotent re-run).
//! - On error: log via `tracing`, continue with the next file. Returns
//!   summary stats so callers can surface what was migrated.

use std::fmt::Write as _;
use std::io::Read as _;
use std::path::Path;
use std::time::SystemTime;

use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::profile_store::Sidecar;
use vortix_core::profile::ProtocolKind;

/// Stats returned by [`migrate_legacy_profiles`].
#[derive(Debug, Default, Clone)]
pub struct MigrationStats {
    /// Profiles that already had sidecars (no-op).
    pub already_migrated: u32,
    /// New sidecars written.
    pub created: u32,
    /// Files that errored during migration (skipped — original untouched).
    pub failed: u32,
    /// Files that didn't match a known extension (skipped silently).
    pub ignored: u32,
}

/// Walk `profiles_dir` and create sidecars for any `.conf` / `.ovpn` files
/// that lack one. Safe to call repeatedly.
///
/// # Errors
///
/// Returns the underlying `io::Error` only when the directory itself is
/// unreadable; per-file errors are logged + counted in
/// [`MigrationStats::failed`].
pub fn migrate_legacy_profiles(profiles_dir: &Path) -> std::io::Result<MigrationStats> {
    let mut stats = MigrationStats::default();
    if !profiles_dir.exists() {
        return Ok(stats);
    }

    for entry in std::fs::read_dir(profiles_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(target: "vortix::migration", error = %e, "failed to read directory entry");
                stats.failed = stats.failed.saturating_add(1);
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            stats.ignored = stats.ignored.saturating_add(1);
            continue;
        };
        let protocol = match ext {
            "conf" => ProtocolKind::WireGuard,
            "ovpn" => ProtocolKind::OpenVpn,
            _ => {
                stats.ignored = stats.ignored.saturating_add(1);
                continue;
            }
        };
        let Some(display_name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            stats.ignored = stats.ignored.saturating_add(1);
            continue;
        };

        let sidecar_path = profiles_dir.join(format!("{display_name}.meta.toml"));
        if sidecar_path.exists() {
            stats.already_migrated = stats.already_migrated.saturating_add(1);
            continue;
        }

        match write_sidecar_for(&path, &display_name, protocol, &sidecar_path) {
            Ok(()) => {
                stats.created = stats.created.saturating_add(1);
                info!(
                    target: "vortix::migration",
                    profile = %display_name,
                    protocol = %protocol,
                    "wrote sidecar"
                );
            }
            Err(e) => {
                stats.failed = stats.failed.saturating_add(1);
                warn!(
                    target: "vortix::migration",
                    profile = %display_name,
                    error = %e,
                    "sidecar write failed"
                );
            }
        }
    }

    Ok(stats)
}

fn write_sidecar_for(
    config_path: &Path,
    display_name: &str,
    protocol: ProtocolKind,
    sidecar_path: &Path,
) -> std::io::Result<()> {
    let profile_id = stable_profile_id(config_path, display_name)?;
    let imported_at = std::fs::metadata(config_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .or(Some(SystemTime::now()));

    let sidecar = Sidecar {
        schema_version: Sidecar::SCHEMA_VERSION,
        profile_id,
        display_name: display_name.to_string(),
        protocol,
        group: None,
        source: Some("migration:v1".to_string()),
        imported_at,
        last_used: None,
    };

    let text = toml::to_string_pretty(&sidecar)
        .map_err(|e| std::io::Error::other(format!("toml serialise: {e}")))?;

    // Atomic-ish write — temp + rename so partial writes don't strand the
    // user with a corrupt sidecar.
    let tmp = sidecar_path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, sidecar_path)?;
    Ok(())
}

/// SHA-256 of `display_name || first 4 KiB of file body`, hex-encoded.
/// Stable across renames-to-same-name + content-identical re-imports.
fn stable_profile_id(config_path: &Path, display_name: &str) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(display_name.as_bytes());
    hasher.update(b"\0");

    let mut file = std::fs::File::open(config_path)?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf)?;
    hasher.update(&buf[..n]);

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn empty_dir_returns_zero_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.already_migrated, 0);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn nonexistent_dir_returns_zero_stats() {
        let tmp = tempfile::tempdir().unwrap();
        let nope = tmp.path().join("does-not-exist");
        let stats = migrate_legacy_profiles(&nope).unwrap();
        assert_eq!(stats.created, 0);
    }

    #[test]
    fn creates_sidecars_for_bare_conf_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("corp.conf"),
            b"[Interface]\nPrivateKey = AAA\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("home.ovpn"),
            b"client\nremote example.com\n",
        )
        .unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 2);
        assert!(tmp.path().join("corp.meta.toml").exists());
        assert!(tmp.path().join("home.meta.toml").exists());

        // Sidecar content sanity.
        let corp = fs::read_to_string(tmp.path().join("corp.meta.toml")).unwrap();
        assert!(corp.contains("display_name = \"corp\""));
        assert!(corp.contains("protocol = \"WireGuard\""));
        assert!(corp.contains("source = \"migration:v1\""));
    }

    #[test]
    fn idempotent_on_rerun() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();

        let first = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(first.created, 1);
        assert_eq!(first.already_migrated, 0);

        let second = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(second.created, 0);
        assert_eq!(second.already_migrated, 1);
    }

    #[test]
    fn ignores_unknown_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("notes.txt"), b"hi").unwrap();
        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.ignored, 1);
        assert!(!tmp.path().join("notes.meta.toml").exists());
    }

    #[test]
    fn stable_id_consistent_for_same_input() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("corp.conf");
        fs::write(&path, b"[Interface]\nFoo = bar\n").unwrap();
        let id1 = stable_profile_id(&path, "corp").unwrap();
        let id2 = stable_profile_id(&path, "corp").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64);
    }

    #[test]
    fn stable_id_differs_for_different_content() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.conf");
        let b = tmp.path().join("b.conf");
        fs::write(&a, b"hello").unwrap();
        fs::write(&b, b"world").unwrap();
        let id_a = stable_profile_id(&a, "corp").unwrap();
        let id_b = stable_profile_id(&b, "corp").unwrap();
        assert_ne!(id_a, id_b);
    }

    // Pathology coverage (plan 007 U3): the rollout depends on
    // `migrate_legacy_profiles` never panicking on a misshapen profile dir.
    // These tests pin that behaviour explicitly so a future change can't
    // silently regress it.

    #[test]
    fn malformed_sidecar_is_treated_as_already_migrated() {
        // If a `.meta.toml` already exists next to a `.conf`, the function
        // must not attempt to overwrite it — even if the existing sidecar
        // is malformed. The repair path is `vortix migrate`, not implicit
        // overwrite.
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
        fs::write(tmp.path().join("corp.meta.toml"), b"this is not toml { ]").unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 0);
        assert_eq!(stats.already_migrated, 1);

        // Original sidecar is untouched.
        let body = fs::read_to_string(tmp.path().join("corp.meta.toml")).unwrap();
        assert_eq!(body, "this is not toml { ]");
    }

    #[test]
    fn unreadable_profile_dir_returns_err_not_panic() {
        // A directory path that points at an existing *file* (not a dir)
        // surfaces an io::Error rather than panicking — main.rs's match
        // logs it and continues startup.
        let tmp = tempfile::tempdir().unwrap();
        let file_masquerading_as_dir = tmp.path().join("not-a-dir");
        fs::write(&file_masquerading_as_dir, b"just a file").unwrap();

        let result = migrate_legacy_profiles(&file_masquerading_as_dir);
        // Either Err (read_dir refuses) or Ok with zero stats (path
        // existed but had no entries). Both are acceptable — the only
        // unacceptable outcome is a panic, which would happen before this
        // assertion runs.
        if let Ok(stats) = result {
            assert_eq!(stats.created, 0);
        }
        // Err is also acceptable — read_dir refuses on most platforms.
    }

    #[test]
    fn nested_directories_inside_profiles_dir_are_ignored() {
        // `read_dir` returns sub-directories too; we skip non-files instead
        // of recursing or panicking.
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("subdir")).unwrap();
        fs::write(tmp.path().join("subdir").join("buried.conf"), b"x").unwrap();
        fs::write(tmp.path().join("surface.conf"), b"[Interface]\n").unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        // Only the top-level surface.conf gets a sidecar; subdir is skipped.
        assert_eq!(stats.created, 1);
        assert!(tmp.path().join("surface.meta.toml").exists());
        assert!(!tmp.path().join("subdir.meta.toml").exists());
    }

    #[test]
    fn extensionless_files_are_ignored_not_failed() {
        // Files with no extension (e.g., README) increment `ignored`, not
        // `failed`. This keeps the warning log clean for the common case
        // of users dropping notes into the profiles dir.
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("README"), b"notes").unwrap();
        fs::write(tmp.path().join("real.conf"), b"[Interface]\n").unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();
        assert_eq!(stats.created, 1);
        assert_eq!(stats.ignored, 1);
        assert_eq!(stats.failed, 0);
    }

    #[cfg(unix)]
    #[test]
    fn read_only_profile_dir_marks_failed_without_panic() {
        // chmod 0500: readable, not writable. read_dir succeeds; the
        // sidecar write fails. Per-file errors increment `failed` and
        // continue.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();

        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o500);
        fs::set_permissions(tmp.path(), perms).unwrap();

        let stats = migrate_legacy_profiles(tmp.path()).unwrap();

        // Restore writable perms so tempdir cleanup succeeds.
        let mut perms = fs::metadata(tmp.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(tmp.path(), perms).unwrap();

        assert_eq!(stats.created, 0);
        assert_eq!(stats.failed, 1);
        // Original .conf is untouched (we never write to it).
        assert!(tmp.path().join("corp.conf").exists());
    }
}
