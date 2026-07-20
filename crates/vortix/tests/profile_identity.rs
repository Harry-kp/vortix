use std::time::{Duration, Instant};

use vortix::state::{ProfilePresence, ProfilePresenceTracker};
use vortix::vortix_config::migrate_legacy_profiles;
use vortix::vortix_config::profile_store::{
    FsProfileStore, ProfileStore, ProfileStoreError, Sidecar,
};
use vortix::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

fn id(byte: u8) -> ProfileId {
    ProfileId::parse(format!("{byte:02x}").repeat(32)).unwrap()
}

#[test]
fn pre_sidecar_and_current_sidecar_resolve_to_one_stable_identity() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("corp.conf"), b"[Interface]\n").unwrap();
    migrate_legacy_profiles(tmp.path()).unwrap();
    let store = FsProfileStore::new(tmp.path().to_path_buf());
    let first = store.resolve_display_name("corp").unwrap();
    migrate_legacy_profiles(tmp.path()).unwrap();
    assert_eq!(store.resolve_display_name("corp").unwrap(), first);
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn rename_changes_boundary_name_not_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let profiles = tmp.path().join("profiles");
    let store = FsProfileStore::new(profiles);
    let profile = Profile::new(id(7), "corp", ProtocolKind::WireGuard, "ignored".into());
    store.insert(&profile, b"[Interface]\n").unwrap();
    let renamed = store.rename(&id(7), "work").unwrap();
    assert_eq!(renamed.id, id(7));
    assert_eq!(store.resolve_display_name("work").unwrap(), id(7));
    assert!(store.resolve_display_name("corp").is_err());
}

#[test]
fn duplicate_and_malformed_sidecars_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let profile_id = id(9);
    for name in ["a", "b"] {
        std::fs::write(tmp.path().join(format!("{name}.conf")), b"x").unwrap();
        let sidecar = Sidecar {
            schema_version: Sidecar::SCHEMA_VERSION,
            profile_id: profile_id.to_string(),
            display_name: name.to_string(),
            protocol: ProtocolKind::WireGuard,
            config_file: Some(format!("{name}.conf")),
            group: None,
            source: None,
            imported_at: None,
            last_used: None,
        };
        std::fs::write(
            tmp.path().join(format!("{name}.meta.toml")),
            toml::to_string(&sidecar).unwrap(),
        )
        .unwrap();
    }
    let store = FsProfileStore::new(tmp.path().to_path_buf());
    assert!(matches!(
        store.list(),
        Err(ProfileStoreError::DuplicateId { .. })
    ));

    std::fs::write(tmp.path().join("b.meta.toml"), b"profile_id = [").unwrap();
    assert!(matches!(
        store.list(),
        Err(ProfileStoreError::MalformedSidecar { .. })
    ));
}

#[test]
fn transient_external_rename_keeps_identity_and_stable_loss_is_missing() {
    let start = Instant::now();
    let mut tracker = ProfilePresenceTracker::new("corp.conf".into(), Duration::from_millis(250));
    tracker.observe_missing(start);
    tracker.observe_path(".corp.conf.swp".into());
    assert!(matches!(tracker.state(), ProfilePresence::Present(_)));

    tracker.observe_missing(start);
    tracker.settle(start + Duration::from_millis(251));
    assert_eq!(tracker.state(), &ProfilePresence::Missing);
}

#[test]
fn opaque_id_validation_rejects_names_and_uppercase() {
    assert!(ProfileId::parse("corp").is_err());
    assert!(ProfileId::parse("A".repeat(64)).is_err());
    assert!(ProfileId::parse("ab".repeat(32)).is_ok());
}
