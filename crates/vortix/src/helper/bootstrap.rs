//! Fixed-path package bootstrap for staged Background-mode enrollment.

#![allow(
    unsafe_code,
    reason = "root artifact verification requires no-follow descriptor opens and credential syscalls"
)]

use std::ffi::CString;
use std::fs::File;
use std::io::Read as _;
use std::os::fd::FromRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::enrollment_store::RootEnrollmentStore;
use super::root_store::RootOwnedJsonStore;
use super::validate::{
    ArtifactFact, ArtifactKind, InstallManifest, InstallRequest, PlatformLayout,
};
use super::INSTALL_SCHEMA_VERSION;
use crate::vortix_core::privileged::{AuthorityBinding, BootScope, LeaseId, OperationDigest};

pub const MAX_INSTALL_REQUEST_BYTES: u64 = 16 * 1024;
const MAX_INSTALL_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_INSTALLED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DAEMON_ENVIRONMENT_BYTES: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapStageReceipt {
    pub schema_version: u16,
    pub owner_uid: u32,
    pub layout: PlatformLayout,
    pub manifest_generation: u64,
    pub manifest_digest: OperationDigest,
    pub staged_unenrolled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapReserveReceipt {
    pub schema_version: u16,
    pub owner_uid: u32,
    pub layout: PlatformLayout,
    pub manifest_generation: u64,
    pub manifest_digest: OperationDigest,
    pub authority_epoch: crate::vortix_core::control::AuthorityEpoch,
    pub authority_binding: AuthorityBinding,
    pub candidate_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootstrapCommitReceipt {
    pub schema_version: u16,
    pub owner_uid: u32,
    pub layout: PlatformLayout,
    pub manifest_generation: u64,
    pub manifest_digest: OperationDigest,
    pub authority_epoch: crate::vortix_core::control::AuthorityEpoch,
    pub authority_binding: AuthorityBinding,
    pub authority_enrolled: bool,
}

/// Verify one package-supplied installation and persist only staged authority.
///
/// The request is bounded and strict. All privileged paths are selected from
/// the platform layout; no request field can name a file, executable, service,
/// command, argument, environment entry, or network resource.
pub fn stage_package_from_reader(
    reader: impl std::io::Read,
) -> Result<BootstrapStageReceipt, BootstrapError> {
    let (request, current_layout, manifest) = verify_package_request(reader)?;
    ensure_root_state_directory(current_layout)?;
    let _authority_lock = acquire_authority_lock(current_layout, request.owner_uid())?;
    RootEnrollmentStore::root_owned(current_layout)
        .stage(&request, &manifest)
        .map_err(|_| BootstrapError::EnrollmentState)?;

    Ok(BootstrapStageReceipt {
        schema_version: INSTALL_SCHEMA_VERSION,
        owner_uid: request.owner_uid(),
        layout: current_layout,
        manifest_generation: manifest.generation(),
        manifest_digest: manifest.digest(),
        staged_unenrolled: true,
    })
}

pub fn reserve_package_from_reader(
    reader: impl std::io::Read,
) -> Result<BootstrapReserveReceipt, BootstrapError> {
    let (request, current_layout, manifest) = verify_package_request(reader)?;
    ensure_root_state_directory(current_layout)?;
    let _authority_lock = acquire_authority_lock(current_layout, request.owner_uid())?;
    let boot_scope = current_boot_scope()?;
    let lease_id = LeaseId::new(random_array()?);
    let manager_instance_nonce = random_array()?;
    let reservation = RootEnrollmentStore::root_owned(current_layout)
        .reserve(&request, boot_scope, lease_id, manager_instance_nonce)
        .map_err(|_| BootstrapError::EnrollmentState)?;
    persist_daemon_environment(current_layout, reservation)?;

    Ok(BootstrapReserveReceipt {
        schema_version: INSTALL_SCHEMA_VERSION,
        owner_uid: request.owner_uid(),
        layout: current_layout,
        manifest_generation: manifest.generation(),
        manifest_digest: manifest.digest(),
        authority_epoch: reservation.authority_epoch(),
        authority_binding: reservation.binding(),
        candidate_ready: true,
    })
}

pub fn commit_package_from_reader(
    reader: impl std::io::Read,
    expected_epoch: u64,
) -> Result<BootstrapCommitReceipt, BootstrapError> {
    let authority_epoch = crate::vortix_core::control::AuthorityEpoch(expected_epoch);
    if expected_epoch == 0 {
        return Err(BootstrapError::InvalidAuthorityEpoch);
    }
    let (request, current_layout, manifest) = verify_package_request(reader)?;
    ensure_root_state_directory(current_layout)?;
    let _authority_lock = acquire_authority_lock(current_layout, request.owner_uid())?;
    let reservation = RootEnrollmentStore::root_owned(current_layout)
        .commit_epoch(&request, authority_epoch)
        .map_err(|_| BootstrapError::EnrollmentState)?;
    persist_daemon_environment(current_layout, reservation)?;

    Ok(BootstrapCommitReceipt {
        schema_version: INSTALL_SCHEMA_VERSION,
        owner_uid: request.owner_uid(),
        layout: current_layout,
        manifest_generation: manifest.generation(),
        manifest_digest: manifest.digest(),
        authority_epoch,
        authority_binding: reservation.binding(),
        authority_enrolled: true,
    })
}

fn verify_package_request(
    reader: impl std::io::Read,
) -> Result<(InstallRequest, PlatformLayout, InstallManifest), BootstrapError> {
    let request_bytes = read_bounded(reader, MAX_INSTALL_REQUEST_BYTES)?;
    let request: InstallRequest =
        serde_json::from_slice(&request_bytes).map_err(|_| BootstrapError::InvalidRequest)?;
    let current_layout = PlatformLayout::current().ok_or(BootstrapError::UnsupportedPlatform)?;
    if request.layout() != current_layout {
        return Err(BootstrapError::WrongPlatformLayout);
    }
    verify_root_and_original_caller(request.owner_uid())?;
    verify_environment()?;
    let manifest = load_verified_manifest(current_layout)?;
    request.verify_manifest(&manifest)?;

    for kind in [
        ArtifactKind::Daemon,
        ArtifactKind::Helper,
        ArtifactKind::Bootstrap,
    ] {
        let _ = verify_installed_artifact(current_layout, kind, &manifest)?;
    }
    verify_running_bootstrap(current_layout)?;
    Ok((request, current_layout, manifest))
}

fn acquire_authority_lock(layout: PlatformLayout, owner_uid: u32) -> Result<File, BootstrapError> {
    crate::authority_lock::install_and_acquire(layout, owner_uid).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            BootstrapError::AuthorityLockBusy
        } else {
            BootstrapError::AuthorityLock
        }
    })
}

fn current_boot_scope() -> Result<BootScope, BootstrapError> {
    let identity = crate::utils::boot_identity().ok_or(BootstrapError::MissingBootIdentity)?;
    let mut material = Vec::with_capacity(identity.len() + 24);
    material.extend_from_slice(b"vortix-helper-boot-v1\0");
    material.extend_from_slice(identity.as_bytes());
    let digest = OperationDigest::of_bytes(&material).as_bytes();
    let mut scope = [0_u8; 16];
    scope.copy_from_slice(&digest[..16]);
    Ok(BootScope::new(scope))
}

fn random_array<const N: usize>() -> Result<[u8; N], BootstrapError> {
    let mut source = File::open("/dev/urandom")?;
    let metadata = source.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.uid() != 0 {
        return Err(BootstrapError::Randomness);
    }
    let mut bytes = [0_u8; N];
    source.read_exact(&mut bytes)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(BootstrapError::Randomness);
    }
    Ok(bytes)
}

fn persist_daemon_environment(
    layout: PlatformLayout,
    reservation: super::enrollment_store::AuthorityReservation,
) -> Result<(), BootstrapError> {
    let mut nonce = String::with_capacity(64);
    for byte in reservation.manager_instance_nonce() {
        use std::fmt::Write as _;
        let _ = write!(&mut nonce, "{byte:02x}");
    }
    let contents = format!("VORTIX_MANAGER_NONCE_HEX={nonce}\n");
    RootOwnedJsonStore::new(
        layout.daemon_environment(),
        0,
        layout.root_state_dir_mode(),
        MAX_DAEMON_ENVIRONMENT_BYTES,
        "daemon-env",
    )
    .expect("fixed daemon environment path is absolute and valid")
    .write(contents.as_bytes())
    .map_err(|_| BootstrapError::RootStore)?;
    Ok(())
}

fn verify_root_and_original_caller(owner_uid: u32) -> Result<(), BootstrapError> {
    let (real_uid, effective_uid) = unsafe { (libc::getuid(), libc::geteuid()) };
    if real_uid != 0 || effective_uid != 0 {
        return Err(BootstrapError::RequiresRoot);
    }
    let sudo_uid = std::env::var_os("SUDO_UID")
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
        .ok_or(BootstrapError::MissingOriginalCaller)?;
    if sudo_uid != owner_uid {
        return Err(BootstrapError::WrongOriginalCaller);
    }
    Ok(())
}

fn verify_environment() -> Result<(), BootstrapError> {
    if std::env::vars_os().any(|(name, _)| unsafe_environment_name(name.as_os_str().as_bytes())) {
        return Err(BootstrapError::UnsafeEnvironment);
    }
    Ok(())
}

fn unsafe_environment_name(name: &[u8]) -> bool {
    name.starts_with(b"LD_")
        || name.starts_with(b"DYLD_")
        || name.starts_with(b"VORTIX_")
        || matches!(name, b"RUSTFLAGS" | b"RUSTDOCFLAGS" | b"RUST_LOG")
}

fn ensure_root_state_directory(layout: PlatformLayout) -> Result<(), BootstrapError> {
    let state_file = Path::new(layout.root_enrollment());
    let directory = state_file
        .parent()
        .ok_or(BootstrapError::UnsafeStateDirectory)?;
    let created = match std::fs::create_dir(directory) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    if created {
        std::fs::set_permissions(
            directory,
            std::fs::Permissions::from_mode(layout.root_state_dir_mode()),
        )?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != layout.root_state_dir_mode()
    {
        return Err(BootstrapError::UnsafeStateDirectory);
    }
    Ok(())
}

pub(super) fn load_verified_manifest(
    layout: PlatformLayout,
) -> Result<InstallManifest, BootstrapError> {
    let manifest_bytes = read_root_owned_regular_file(
        Path::new(layout.install_manifest()),
        0,
        MAX_INSTALL_MANIFEST_BYTES,
        false,
    )?;
    serde_json::from_slice(&manifest_bytes).map_err(|_| BootstrapError::InvalidManifest)
}

pub(super) fn verify_installed_artifact(
    layout: PlatformLayout,
    kind: ArtifactKind,
    manifest: &InstallManifest,
) -> Result<OperationDigest, BootstrapError> {
    let path = match kind {
        ArtifactKind::Daemon => layout.daemon_path(),
        ArtifactKind::Helper => layout.helper_path(),
        ArtifactKind::Bootstrap => layout.bootstrap_path(),
    };
    let mut file =
        open_root_owned_regular_file(Path::new(path), 0, MAX_INSTALLED_ARTIFACT_BYTES, true)?;
    let metadata = file.metadata()?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let digest = OperationDigest::from_sha256(hash.finalize().into());
    let fact = ArtifactFact::from_os_verifier(
        kind,
        Path::new(path).to_owned(),
        0,
        metadata.permissions().mode() & 0o777,
        digest,
        false,
    );
    fact.validate(layout, manifest)?;
    Ok(digest)
}

fn verify_running_bootstrap(layout: PlatformLayout) -> Result<(), BootstrapError> {
    let running = std::fs::metadata("/proc/self/exe")
        .or_else(|_| std::env::current_exe().and_then(std::fs::metadata))?;
    let installed = open_root_owned_regular_file(
        Path::new(layout.bootstrap_path()),
        0,
        MAX_INSTALLED_ARTIFACT_BYTES,
        true,
    )?
    .metadata()?;
    if running.dev() != installed.dev() || running.ino() != installed.ino() {
        return Err(BootstrapError::WrongBootstrapExecutable);
    }
    Ok(())
}

fn read_root_owned_regular_file(
    path: &Path,
    expected_owner_uid: u32,
    max_bytes: u64,
    executable: bool,
) -> Result<Vec<u8>, BootstrapError> {
    let file = open_root_owned_regular_file(path, expected_owner_uid, max_bytes, executable)?;
    read_bounded(file, max_bytes)
}

fn open_root_owned_regular_file(
    path: &Path,
    expected_owner_uid: u32,
    max_bytes: u64,
    executable: bool,
) -> Result<File, BootstrapError> {
    let encoded = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| BootstrapError::UnsafeInstalledFile)?;
    let fd = unsafe {
        libc::open(
            encoded.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != expected_owner_uid
        || metadata.nlink() != 1
        || mode & 0o022 != 0
        || executable && mode & 0o500 != 0o500
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(BootstrapError::UnsafeInstalledFile);
    }
    Ok(file)
}

fn read_bounded(mut reader: impl std::io::Read, max_bytes: u64) -> Result<Vec<u8>, BootstrapError> {
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut reader)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(BootstrapError::Capacity);
    }
    Ok(bytes)
}

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("the install request is empty, malformed, or contains unknown fields")]
    InvalidRequest,
    #[error("the package manifest is malformed")]
    InvalidManifest,
    #[error("the install request or manifest exceeds its fixed size")]
    Capacity,
    #[error("this operating system has no supported package bootstrap")]
    UnsupportedPlatform,
    #[error("the requested package layout does not match this operating system")]
    WrongPlatformLayout,
    #[error("the package bootstrap must run through system sudo as root")]
    RequiresRoot,
    #[error("the package bootstrap cannot verify the original sudo caller")]
    MissingOriginalCaller,
    #[error("the install owner does not match the original sudo caller")]
    WrongOriginalCaller,
    #[error("the package bootstrap received an unsafe environment")]
    UnsafeEnvironment,
    #[error("the package state directory is not root-owned mode 0700")]
    UnsafeStateDirectory,
    #[error("a package artifact is not a safe root-owned regular file")]
    UnsafeInstalledFile,
    #[error("the running bootstrap is not the installed package bootstrap")]
    WrongBootstrapExecutable,
    #[error("the root-owned enrollment record could not be staged safely")]
    EnrollmentState,
    #[error("the root-controlled authority transition lock could not be installed safely")]
    AuthorityLock,
    #[error("another Vortix authority transition is in progress; retry after it completes")]
    AuthorityLockBusy,
    #[error("OS boot identity is unavailable")]
    MissingBootIdentity,
    #[error("authority epoch must be non-zero")]
    InvalidAuthorityEpoch,
    #[error("the package bootstrap could not obtain kernel randomness")]
    Randomness,
    #[error("the package bootstrap could not persist the service environment")]
    RootStore,
    #[error("package validation failed: {0}")]
    Install(#[from] super::validate::InstallError),
    #[error("package bootstrap I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority_binding() -> AuthorityBinding {
        AuthorityBinding::new(
            crate::vortix_core::control::AuthorityEpoch(9),
            BootScope::new([1; 16]),
            LeaseId::new([2; 32]),
            OperationDigest::of_bytes(b"service-instance"),
        )
        .unwrap()
    }

    #[test]
    fn reserve_receipt_keeps_schema_v1_epoch_alongside_binding() {
        let binding = authority_binding();
        let receipt = BootstrapReserveReceipt {
            schema_version: 1,
            owner_uid: 501,
            layout: PlatformLayout::Linux,
            manifest_generation: 7,
            manifest_digest: OperationDigest::of_bytes(b"manifest"),
            authority_epoch: binding.authority_epoch(),
            authority_binding: binding,
            candidate_ready: true,
        };

        let value = serde_json::to_value(receipt).unwrap();
        assert_eq!(value["authority_epoch"], 9);
        assert_eq!(value["authority_binding"]["authority_epoch"], 9);
    }

    #[test]
    fn commit_receipt_keeps_schema_v1_epoch_alongside_binding() {
        let binding = authority_binding();
        let receipt = BootstrapCommitReceipt {
            schema_version: 1,
            owner_uid: 501,
            layout: PlatformLayout::Linux,
            manifest_generation: 7,
            manifest_digest: OperationDigest::of_bytes(b"manifest"),
            authority_epoch: binding.authority_epoch(),
            authority_binding: binding,
            authority_enrolled: true,
        };

        let value = serde_json::to_value(receipt).unwrap();
        assert_eq!(value["authority_epoch"], 9);
        assert_eq!(value["authority_binding"]["authority_epoch"], 9);
    }

    #[test]
    fn bounded_reader_rejects_empty_and_oversized_input() {
        assert!(matches!(
            read_bounded(&b""[..], 4),
            Err(BootstrapError::Capacity)
        ));
        assert!(matches!(
            read_bounded(&b"12345"[..], 4),
            Err(BootstrapError::Capacity)
        ));
        assert_eq!(read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
    }

    #[test]
    fn privileged_loader_and_vortix_environment_names_are_rejected() {
        for name in [
            b"LD_PRELOAD".as_slice(),
            b"DYLD_INSERT_LIBRARIES",
            b"VORTIX_CONFIG_DIR",
            b"RUSTFLAGS",
            b"RUSTDOCFLAGS",
            b"RUST_LOG",
        ] {
            assert!(unsafe_environment_name(name));
        }
        for name in [b"SUDO_UID".as_slice(), b"LANG", b"TERM", b"PATH"] {
            assert!(!unsafe_environment_name(name));
        }
    }

    #[test]
    fn installed_file_reader_rejects_links_writable_files_and_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        std::fs::write(&path, b"trusted").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let uid = crate::utils::effective_user_group_ids().0;
        assert_eq!(
            read_root_owned_regular_file(&path, uid, 7, true).unwrap(),
            b"trusted"
        );
        assert!(matches!(
            read_root_owned_regular_file(&path, uid, 6, true),
            Err(BootstrapError::UnsafeInstalledFile)
        ));

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o520)).unwrap();
        assert!(matches!(
            read_root_owned_regular_file(&path, uid, 7, true),
            Err(BootstrapError::UnsafeInstalledFile)
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::hard_link(&path, directory.path().join("alias")).unwrap();
        assert!(matches!(
            read_root_owned_regular_file(&path, uid, 7, true),
            Err(BootstrapError::UnsafeInstalledFile)
        ));
    }
}
