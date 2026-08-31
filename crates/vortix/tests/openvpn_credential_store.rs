#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;

use vortix::vortix_config::openvpn_credentials::{
    FsOpenVpnCredentialStore, RememberedOpenVpnCredentials,
};
use vortix::vortix_core::profile::ProfileId;

fn id(byte: u8) -> ProfileId {
    ProfileId::parse(format!("{byte:02x}").repeat(32)).unwrap()
}

fn owner() -> (u32, u32) {
    // SAFETY: these calls only read the process credentials.
    #[allow(unsafe_code)]
    unsafe {
        (libc::geteuid(), libc::getegid())
    }
}

#[test]
fn remembered_credentials_round_trip_by_stable_profile_identity() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (uid, gid) = owner();
    let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
    let credentials = RememberedOpenVpnCredentials::new("alice", "correct horse").unwrap();

    store.replace(&id(1), &credentials).unwrap();

    let loaded = store.load(&id(1), "renamed profile").unwrap().unwrap();
    assert_eq!(loaded.username(), "alice");
    assert_eq!(loaded.password(), "correct horse");
    assert!(store.load(&id(2), "renamed profile").unwrap().is_none());
    assert_eq!(
        std::fs::read(temp.path().join("auth").join(format!("{}.auth", id(1)))).unwrap(),
        b"alice\ncorrect horse\n"
    );
}

#[test]
fn stable_credentials_win_and_ambiguous_legacy_names_do_not_fall_back() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (uid, gid) = owner();
    let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
    let stable = RememberedOpenVpnCredentials::new("stable", "secret").unwrap();
    store.replace(&id(3), &stable).unwrap();

    let auth = temp.path().join("auth");
    std::fs::write(auth.join("team_a.auth"), b"legacy\nsecret\n").unwrap();
    std::fs::set_permissions(
        auth.join("team_a.auth"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    assert_eq!(
        store.load(&id(3), "team_a").unwrap().unwrap().username(),
        "stable"
    );
    assert!(store.load(&id(4), "team/a").unwrap().is_none());
}

#[test]
fn unambiguous_legacy_credentials_load_and_clear_without_crossing_profiles() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (uid, gid) = owner();
    let store = FsOpenVpnCredentialStore::for_owner(temp.path(), uid, gid);
    let auth = temp.path().join("auth");
    std::fs::create_dir(&auth).unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o700)).unwrap();
    let legacy = auth.join("legacy_corp.auth");
    std::fs::write(&legacy, b"legacy-user\nlegacy-password\n").unwrap();
    std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o600)).unwrap();

    let loaded = store.load(&id(5), "legacy_corp").unwrap().unwrap();
    assert_eq!(loaded.username(), "legacy-user");
    assert_eq!(loaded.password(), "legacy-password");

    let other = RememberedOpenVpnCredentials::new("other-user", "other-password").unwrap();
    store.replace(&id(6), &other).unwrap();
    store.clear(&id(5), "legacy_corp").unwrap();

    assert!(!legacy.exists());
    assert!(store.load(&id(5), "legacy_corp").unwrap().is_none());
    assert_eq!(
        store.load(&id(6), "other").unwrap().unwrap().username(),
        "other-user"
    );
}
