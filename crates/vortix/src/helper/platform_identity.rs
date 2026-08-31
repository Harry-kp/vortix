//! OS-owned daemon service identity verification for helper enrollment.

#![allow(
    unsafe_code,
    reason = "Linux helper peer authentication requires SO_PEERCRED"
)]
#![allow(
    dead_code,
    reason = "the verifier is consumed by enrolled helper transport after activation"
)]

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Instant;

use thiserror::Error;

#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: import supports the Linux procfs verifier
use super::bootstrap::{load_verified_manifest, verify_installed_artifact};
use super::enrollment_store::AuthorityReservation;
#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: import supports the Linux procfs verifier
use super::validate::{
    verify_helper_peer, verify_service_instance, ArtifactFact, ArtifactKind, HelperPeerFacts,
    VerifiedServiceFacts, HELPER_SOCKET_MODE,
};
use super::validate::{PlatformLayout, VerifiedHelperPeer};
#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: import supports the Linux procfs verifier
use crate::vortix_core::privileged::ServiceManager;
use crate::vortix_core::privileged::{PlatformVerifiedAuthority, ServiceInstanceClaim};

#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: import supports Linux SO_PEERCRED
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: import supports Linux socket fact checks
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
#[cfg(target_os = "linux")]
// xtask:allow-platform-cfg: import supports Linux helper verification
use std::os::unix::net::UnixStream;

const MAX_PROC_FACT_BYTES: u64 = 1024 * 1024;

#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: procfs+cgroup are the Linux service identity primitives
pub(super) fn verify_daemon_service(
    enrolled_owner: u32,
    observed_uid: u32,
    process_id: u32,
    claim: &ServiceInstanceClaim,
    reservation: AuthorityReservation,
) -> Result<PlatformVerifiedAuthority, PlatformIdentityError> {
    if enrolled_owner == 0
        || observed_uid != enrolled_owner
        || process_id == 0
        || claim.manager() != ServiceManager::Systemd
        || claim.pid() != process_id
        || claim.manager_instance_nonce() != reservation.manager_instance_nonce()
    {
        return Err(PlatformIdentityError::Mismatch);
    }
    let layout = PlatformLayout::Linux;
    let manifest = load_verified_manifest(layout).map_err(|_| PlatformIdentityError::Artifact)?;
    let executable_digest = verify_installed_artifact(layout, ArtifactKind::Daemon, &manifest)
        .map_err(|_| PlatformIdentityError::Artifact)?;
    if claim.executable_digest() != executable_digest {
        return Err(PlatformIdentityError::Mismatch);
    }

    let process_root = Path::new("/proc").join(process_id.to_string());
    let process_executable = std::fs::metadata(process_root.join("exe"))?;
    let installed_executable = std::fs::metadata(layout.daemon_path())?;
    if process_executable.dev() != installed_executable.dev()
        || process_executable.ino() != installed_executable.ino()
    {
        return Err(PlatformIdentityError::Mismatch);
    }
    let start_token = parse_proc_start_token(&read_bounded_file(
        &process_root.join("stat"),
        MAX_PROC_FACT_BYTES,
    )?)?;
    let containment = read_bounded_file(&process_root.join("cgroup"), MAX_PROC_FACT_BYTES)?;
    if !systemd_containment_matches(&containment, enrolled_owner) {
        return Err(PlatformIdentityError::Mismatch);
    }
    let environment = read_bounded_file(&process_root.join("environ"), MAX_PROC_FACT_BYTES)?;
    if manager_nonce_from_environment(&environment) != Some(reservation.manager_instance_nonce()) {
        return Err(PlatformIdentityError::Mismatch);
    }
    verify_root_owned_service_definition(Path::new(layout.daemon_service_definition()))?;

    let facts = VerifiedServiceFacts::from_os_verifier(
        ServiceManager::Systemd,
        observed_uid,
        process_id,
        start_token,
        executable_digest,
        reservation.manager_instance_nonce(),
        true,
        true,
    );
    verify_service_instance(enrolled_owner, claim, &facts)
        .map_err(|_| PlatformIdentityError::Mismatch)
}

#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: SO_PEERCRED and procfs prove the connected root helper process
pub(super) fn verify_helper_service(
    stream: &UnixStream,
    owner_uid: u32,
    layout: PlatformLayout,
    deadline: Instant,
) -> Result<VerifiedHelperPeer, PlatformIdentityError> {
    ensure_before(deadline)?;
    if layout != PlatformLayout::Linux || owner_uid == 0 {
        return Err(PlatformIdentityError::HelperMismatch);
    }
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| PlatformIdentityError::HelperMismatch)?;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 || usize::try_from(length).ok() != Some(std::mem::size_of::<libc::ucred>()) {
        return Err(PlatformIdentityError::HelperMismatch);
    }
    let credentials = unsafe { credentials.assume_init() };
    let peer_pid = u32::try_from(credentials.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or(PlatformIdentityError::HelperMismatch)?;

    ensure_before(deadline)?;
    let manifest = load_verified_manifest(layout).map_err(|_| PlatformIdentityError::Artifact)?;
    ensure_before(deadline)?;
    let helper_digest = verify_installed_artifact(layout, ArtifactKind::Helper, &manifest)
        .map_err(|_| PlatformIdentityError::Artifact)?;
    ensure_before(deadline)?;
    let installed = std::fs::metadata(layout.helper_path())?;
    let running = std::fs::metadata(Path::new("/proc").join(peer_pid.to_string()).join("exe"))?;
    if running.dev() != installed.dev() || running.ino() != installed.ino() {
        return Err(PlatformIdentityError::HelperMismatch);
    }
    ensure_before(deadline)?;
    let start_token = parse_proc_start_token(&read_bounded_file(
        &Path::new("/proc").join(peer_pid.to_string()).join("stat"),
        MAX_PROC_FACT_BYTES,
    )?)?;
    ensure_before(deadline)?;
    let socket = std::fs::symlink_metadata(layout.helper_socket())?;
    if !socket.file_type().is_socket()
        || socket.uid() != owner_uid
        || socket.permissions().mode() & 0o777 != HELPER_SOCKET_MODE
    {
        return Err(PlatformIdentityError::HelperMismatch);
    }
    ensure_before(deadline)?;
    let artifact = ArtifactFact::from_os_verifier(
        ArtifactKind::Helper,
        Path::new(layout.helper_path()).to_owned(),
        installed.uid(),
        installed.permissions().mode() & 0o777,
        helper_digest,
        false,
    );
    let facts = HelperPeerFacts::from_os_verifier(
        credentials.uid,
        peer_pid,
        start_token,
        Path::new(layout.helper_socket()).to_owned(),
        socket.uid(),
        socket.permissions().mode() & 0o777,
        artifact,
    );
    let verified = verify_helper_peer(owner_uid, layout, &manifest, &facts)
        .map_err(|_| PlatformIdentityError::HelperMismatch)?;
    ensure_before(deadline)?;
    Ok(verified)
}

#[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: macOS stays fail-closed until launchd process identity and signing proof ship
pub(super) fn verify_helper_service(
    _stream: &std::os::unix::net::UnixStream,
    _owner_uid: u32,
    _layout: PlatformLayout,
    _deadline: Instant,
) -> Result<VerifiedHelperPeer, PlatformIdentityError> {
    Err(PlatformIdentityError::UnsupportedPlatform)
}

fn ensure_before(deadline: Instant) -> Result<(), PlatformIdentityError> {
    if Instant::now() >= deadline {
        Err(PlatformIdentityError::DeadlineExpired)
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: macOS activation stays fail-closed until its signing+launchd verifier ships
pub(super) fn verify_daemon_service(
    _owner_uid: u32,
    _peer_uid: u32,
    _peer_pid: u32,
    _claim: &ServiceInstanceClaim,
    _reservation: AuthorityReservation,
) -> Result<PlatformVerifiedAuthority, PlatformIdentityError> {
    Err(PlatformIdentityError::UnsupportedPlatform)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PlatformIdentityError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(PlatformIdentityError::Capacity);
    }
    Ok(bytes)
}

fn parse_proc_start_token(bytes: &[u8]) -> Result<u64, PlatformIdentityError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PlatformIdentityError::MalformedFact)?;
    let close = text
        .rfind(") ")
        .ok_or(PlatformIdentityError::MalformedFact)?;
    // The suffix begins at field 3 (`state`); starttime is Linux stat field 22.
    text[close + 2..]
        .split_ascii_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or(PlatformIdentityError::MalformedFact)
}

fn systemd_containment_matches(bytes: &[u8], owner_uid: u32) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let expected = format!("/system.slice/vortix-daemon@{owner_uid}.service");
    text.lines().any(|line| {
        line.split_once(':')
            .and_then(|(_, rest)| rest.split_once(':'))
            .is_some_and(|(_, path)| path == expected)
    })
}

fn manager_nonce_from_environment(bytes: &[u8]) -> Option<[u8; 32]> {
    const PREFIX: &[u8] = b"VORTIX_MANAGER_NONCE_HEX=";
    let mut found = None;
    for entry in bytes.split(|byte| *byte == 0) {
        let Some(value) = entry.strip_prefix(PREFIX) else {
            continue;
        };
        if found.is_some() || value.len() != 64 {
            return None;
        }
        let mut nonce = [0_u8; 32];
        for (output, pair) in nonce.iter_mut().zip(value.chunks_exact(2)) {
            *output = decode_hex(pair[0])?.checked_mul(16)? + decode_hex(pair[1])?;
        }
        if nonce == [0; 32] {
            return None;
        }
        found = Some(nonce);
    }
    found
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn verify_root_owned_service_definition(path: &Path) -> Result<(), PlatformIdentityError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(PlatformIdentityError::UnsafeServiceDefinition);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(super) enum PlatformIdentityError {
    #[error("daemon service identity does not match OS-owned facts")]
    Mismatch,
    #[error("helper process, socket, or installed artifact does not match OS-owned facts")]
    HelperMismatch,
    #[error("daemon service identity fact is malformed")]
    MalformedFact,
    #[error("daemon service identity fact exceeds its fixed size")]
    Capacity,
    #[error("installed daemon artifact is unavailable or untrusted")]
    Artifact,
    #[error("daemon service definition is not a safe root-owned file")]
    UnsafeServiceDefinition,
    #[error("this platform has no enrolled service verifier")]
    UnsupportedPlatform,
    #[error("helper identity verification exceeded the caller's absolute deadline")]
    DeadlineExpired,
    #[error("daemon service identity I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_parser_uses_field_22_even_when_comm_contains_spaces_and_parens() {
        let mut fields = vec!["S".to_string()];
        fields.extend((4..=21).map(|value| value.to_string()));
        fields.push("424242".into());
        fields.extend(["23".into(), "24".into()]);
        let line = format!("77 (vortix ) daemon) {}", fields.join(" "));
        assert_eq!(parse_proc_start_token(line.as_bytes()).unwrap(), 424_242);
        assert!(parse_proc_start_token(b"77 malformed").is_err());
    }

    #[test]
    fn cgroup_match_is_exact_to_enrolled_uid_unit() {
        assert!(systemd_containment_matches(
            b"0::/system.slice/vortix-daemon@501.service\n",
            501
        ));
        assert!(!systemd_containment_matches(
            b"0::/user.slice/vortix-daemon@501.service.evil\n",
            501
        ));
        assert!(!systemd_containment_matches(
            b"0::/user.slice/user-501.slice/user@501.service/app.slice/vortix-daemon@501.service\n",
            501
        ));
        assert!(!systemd_containment_matches(
            b"0::/system.slice/vortix-daemon@502.service\n",
            501
        ));
    }

    #[test]
    fn manager_nonce_requires_one_exact_nonzero_hex_value() {
        let encoded = format!("A=1\0VORTIX_MANAGER_NONCE_HEX={}\0", "07".repeat(32));
        assert_eq!(
            manager_nonce_from_environment(encoded.as_bytes()),
            Some([7; 32])
        );
        assert!(manager_nonce_from_environment(
            format!(
                "VORTIX_MANAGER_NONCE_HEX={}\0VORTIX_MANAGER_NONCE_HEX={}\0",
                "07".repeat(32),
                "07".repeat(32)
            )
            .as_bytes()
        )
        .is_none());
        assert!(manager_nonce_from_environment(b"VORTIX_MANAGER_NONCE_HEX=zz").is_none());
    }

    #[cfg(not(target_os = "linux"))] // xtask:allow-platform-cfg: unsupported service proof must remain fail-closed
    #[test]
    fn helper_service_identity_is_fail_closed_without_an_os_verifier() {
        let (client, _server) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(matches!(
            verify_helper_service(
                &client,
                501,
                PlatformLayout::MacOs,
                Instant::now() + std::time::Duration::from_secs(1),
            ),
            Err(PlatformIdentityError::UnsupportedPlatform)
        ));
    }
}
