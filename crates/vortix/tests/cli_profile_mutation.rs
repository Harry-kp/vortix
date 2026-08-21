//! Fresh-process coverage for CLI profile mutations.

use std::process::Command;

use vortix::vortix_config::profile_store::{FsProfileStore, ProfileStore};
use vortix::vortix_core::profile::{Profile, ProfileId, ProtocolKind};

fn run_vortix(config_dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_vortix"))
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--quiet")
        .args(args)
        .output()
        .expect("spawn vortix")
}

#[test]
fn cli_rename_and_delete_keep_profile_inventory_coherent_across_processes() {
    let config_dir = tempfile::tempdir().unwrap();
    let profiles_dir = config_dir.path().join("profiles");
    let store = FsProfileStore::new(profiles_dir.clone());
    let profile_id = ProfileId::parse("55".repeat(32)).unwrap();
    let profile = Profile::new(
        profile_id.clone(),
        "corp",
        ProtocolKind::OpenVpn,
        profiles_dir.join("corp.conf"),
    );
    store
        .insert(
            &profile,
            b"client\ndev tun\nproto udp\nremote 1.2.3.4 1194\n",
        )
        .unwrap();

    let rename = run_vortix(config_dir.path(), &["rename", "corp", "work"]);
    assert!(
        rename.status.success(),
        "rename failed: {}",
        String::from_utf8_lossy(&rename.stderr)
    );

    // A newly constructed store represents the next process. Both its
    // sidecar scan and durable inventory must agree on the stable identity.
    let after_rename = FsProfileStore::new(profiles_dir.clone());
    assert_eq!(
        after_rename.resolve_display_name("work").unwrap(),
        profile_id
    );
    assert_eq!(after_rename.list().unwrap().len(), 1);
    assert!(profiles_dir.join("work.conf").exists());
    assert!(profiles_dir.join("work.meta.toml").exists());

    let delete = run_vortix(config_dir.path(), &["delete", "work", "--yes"]);
    assert!(
        delete.status.success(),
        "delete failed: {}",
        String::from_utf8_lossy(&delete.stderr)
    );

    let after_delete = FsProfileStore::new(profiles_dir);
    assert!(after_delete.list().unwrap().is_empty());
    assert!(after_delete.get(&profile_id).is_err());
}
