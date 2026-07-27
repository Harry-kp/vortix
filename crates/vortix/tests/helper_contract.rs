//! U11 privileged-helper wire and staging contract. No test executes a
//! privileged operation or mutates a service manager.

use serde_json::json;
use vortix::helper::{
    negotiate_staged, parse_request, EnrollmentSupport, HelperAuthorityMode, HelperCapability,
    HelperClientHello, HelperError, HelperOp, HelperRequest, InstallManifest, InstallPlan,
    InstallRequest, PackageChannel, PlatformLayout, StagedAuthority, HELPER_LEDGER_MODE,
    HELPER_RUNTIME_DIR_MODE, HELPER_SOCKET_MODE, MAX_HELPER_FRAME_BYTES,
};
use vortix::vortix_core::ipc::CompatibilityRange;
use vortix::vortix_core::privileged::{OperationDigest, ServiceInstanceClaim};

fn service_claim() -> ServiceInstanceClaim {
    ServiceInstanceClaim::systemd(
        42,
        99,
        OperationDigest::of_bytes(b"root-owned daemon"),
        [7; 32],
    )
    .unwrap()
}

fn handshake(required: Vec<HelperCapability>) -> HelperClientHello {
    HelperClientHello::current(501, service_claim(), required)
}

fn manifest() -> InstallManifest {
    InstallManifest::new(
        "0.4.3".into(),
        3,
        OperationDigest::of_bytes(b"daemon"),
        OperationDigest::of_bytes(b"helper"),
        OperationDigest::of_bytes(b"bootstrap"),
        Some(OperationDigest::of_bytes(b"prior manifest")),
    )
    .unwrap()
}

#[test]
fn staged_handshake_tells_the_truth_and_cannot_enable_operations() {
    let hello = negotiate_staged(&handshake(vec![HelperCapability::Handshake])).unwrap();
    assert_eq!(hello.authority_mode, HelperAuthorityMode::Staged);
    assert_eq!(
        hello.enabled_capabilities,
        vec![HelperCapability::Handshake]
    );
    assert!(hello
        .contract_capabilities
        .contains(&HelperCapability::TunnelLifecycle));

    assert!(matches!(
        negotiate_staged(&handshake(vec![HelperCapability::NetworkPolicy])),
        Err(HelperError::CapabilityUnavailable {
            capability: HelperCapability::NetworkPolicy
        })
    ));
}

#[test]
fn incompatible_and_root_owner_handshakes_fail_before_an_operation() {
    let mut incompatible = handshake(Vec::new());
    incompatible.protocol = CompatibilityRange { min: 99, max: 100 };
    assert!(matches!(
        negotiate_staged(&incompatible),
        Err(HelperError::Incompatible { .. })
    ));

    let root = HelperClientHello::current(0, service_claim(), Vec::new());
    assert!(negotiate_staged(&root).is_err());

    let duplicate = handshake(vec![
        HelperCapability::Handshake,
        HelperCapability::Handshake,
    ]);
    assert!(negotiate_staged(&duplicate).is_err());
}

#[test]
fn helper_request_decoder_is_bounded_strict_and_mutation_resistant() {
    let request = HelperRequest {
        id: 1,
        op: HelperOp::Handshake(handshake(vec![HelperCapability::Handshake])),
    };
    let encoded = serde_json::to_vec(&request).unwrap();
    assert!(matches!(
        parse_request(&encoded).unwrap().op,
        HelperOp::Handshake(_)
    ));

    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown["arbitrary_executable"] = json!("/bin/sh");
    assert!(parse_request(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(matches!(
        parse_request(&vec![b' '; MAX_HELPER_FRAME_BYTES + 1]),
        Err(HelperError::FrameTooLarge { .. })
    ));

    for index in 0..encoded.len() {
        let mut mutated = encoded.clone();
        mutated[index] ^= 0x5a;
        assert!(std::panic::catch_unwind(|| parse_request(&mutated)).is_ok());
    }
}

#[test]
fn fixed_layout_and_permissions_are_part_of_the_contract() {
    assert_eq!(HELPER_SOCKET_MODE, 0o600);
    assert_eq!(HELPER_RUNTIME_DIR_MODE, 0o700);
    assert_eq!(HELPER_LEDGER_MODE, 0o600);
    assert_eq!(
        PlatformLayout::Linux.helper_path(),
        "/usr/libexec/vortix/vortix-helper"
    );
    assert_eq!(
        PlatformLayout::MacOs.helper_path(),
        "/Library/PrivilegedHelperTools/com.vortix.helper"
    );
    assert_eq!(manifest().generation(), 3);
}

#[test]
fn every_package_channel_is_explicitly_classified() {
    for supported in [
        PackageChannel::DistroPackage,
        PackageChannel::MacOsSignedPackage,
    ] {
        assert_eq!(supported.enrollment_support(), EnrollmentSupport::Supported);
    }
    for unsupported in [
        PackageChannel::Homebrew,
        PackageChannel::CargoInstall,
        PackageChannel::SourceBuild,
    ] {
        assert_eq!(
            unsupported.enrollment_support(),
            EnrollmentSupport::Unsupported
        );
        assert!(!unsupported.secure_guidance().is_empty());
    }
}

#[test]
fn one_installer_plan_stages_but_never_enrolls() {
    let linux = InstallPlan::build(PlatformLayout::Linux, PackageChannel::DistroPackage).unwrap();
    assert_eq!(linux.authority, StagedAuthority::StagedUnenrolled);
    assert!(InstallPlan::build(PlatformLayout::Linux, PackageChannel::CargoInstall).is_err());
    assert!(InstallPlan::build(PlatformLayout::MacOs, PackageChannel::MacOsSignedPackage).is_ok());

    let request = InstallRequest::new(
        501,
        PlatformLayout::Linux,
        PackageChannel::DistroPackage,
        3,
        OperationDigest::of_bytes(b"manifest"),
        [9; 32],
    )
    .unwrap();
    let value = serde_json::to_value(request).unwrap();
    for forbidden in ["path", "executable", "environment", "shell", "profile"] {
        assert!(value.get(forbidden).is_none());
    }
}

#[test]
fn install_wire_rejects_unknown_fields_root_owner_and_replay_shape() {
    let mut value = json!({
        "schema_version": 1,
        "owner_uid": 501,
        "layout": "linux",
        "channel": "distro_package",
        "manifest_generation": 3,
        "manifest_digest": vec![3_u8; 32],
        "request_nonce": vec![4_u8; 32]
    });
    assert!(serde_json::from_value::<InstallRequest>(value.clone()).is_ok());
    value["environment"] = json!({"PATH": "/tmp"});
    assert!(serde_json::from_value::<InstallRequest>(value).is_err());

    let mut root = serde_json::to_value(
        InstallRequest::new(
            501,
            PlatformLayout::Linux,
            PackageChannel::DistroPackage,
            3,
            OperationDigest::of_bytes(b"manifest"),
            [4; 32],
        )
        .unwrap(),
    )
    .unwrap();
    root["owner_uid"] = json!(0);
    assert!(serde_json::from_value::<InstallRequest>(root).is_err());
}

#[test]
fn staged_binary_has_no_serve_or_operation_entrypoint() {
    let helper = env!("CARGO_BIN_EXE_vortix-helper");
    let version = std::process::Command::new(helper) // xtask:allow-subprocess: black-box staged binary test
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("staged, unenrolled"));

    for argument in ["--serve", "execute", "install"] {
        let output = std::process::Command::new(helper) // xtask:allow-subprocess: black-box staged binary test
            .arg(argument)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78));
    }
}
