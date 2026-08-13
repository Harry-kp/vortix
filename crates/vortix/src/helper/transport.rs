//! Fixed Unix transport for the staged privileged helper.

#![allow(
    unsafe_code,
    reason = "Unix socket ownership, peer credentials, and creation umask require libc"
)]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use thiserror::Error;

use super::descriptor_transport::{receive_request, ReceivedHelperRequest};
use super::enrollment_store::{EnrollmentStoreError, RootEnrollmentAuthority, RootEnrollmentStore};
use super::executor::ProductionHelperExecutor;
use super::platform_identity::verify_daemon_service;
use super::protocol::{
    encode_response_frame, negotiate_candidate, negotiate_staged, HelperCapability, HelperError,
    HelperOp, HelperRequest, HelperResponse, HelperResult, HelperSessionBinding,
};
#[cfg(test)]
use super::protocol::{negotiate_enrolled, STAGED_CAPABILITIES};
use super::validate::{PlatformLayout, HELPER_SOCKET_DIR_MODE, HELPER_SOCKET_MODE};
use super::{replay_store::FsHelperLedgerStore, server::EnrolledHelperSession};
use crate::vortix_core::privileged::{HelperEpoch, PlatformVerifiedAuthority, RootAuthorityLedger};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);

pub fn serve_staged_helper() -> Result<(), HelperTransportError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(HelperTransportError::RequiresRoot);
    }
    let layout = PlatformLayout::current().ok_or(HelperTransportError::UnsupportedPlatform)?;
    let owner_uid = RootEnrollmentStore::root_owned(layout)
        .owner_uid()
        .map_err(|_| HelperTransportError::EnrollmentUnavailable)?;
    let runtime = Path::new(layout.helper_runtime_dir());
    ensure_runtime_root(runtime)?;
    let socket = Path::new(layout.helper_socket());
    remove_stale_socket(socket, owner_uid)?;

    let prior_umask = unsafe { libc::umask(0o177) };
    let bind_result = UnixListener::bind(socket);
    unsafe { libc::umask(prior_umask) };
    let listener = bind_result?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(HELPER_SOCKET_MODE))?;
    chown_socket(socket, owner_uid)?;
    validate_socket(socket, owner_uid)?;
    let helper_epoch = random_helper_epoch()?;

    for connection in listener.incoming() {
        let mut connection = connection?;
        connection.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
        connection.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
        let peer = peer_credentials(&connection)?;
        if peer.uid != owner_uid {
            continue;
        }
        let authority = match RootEnrollmentStore::root_owned(layout).authority_for_owner(owner_uid)
        {
            Ok(authority) => Some(authority),
            Err(EnrollmentStoreError::NotEnrolled) => None,
            Err(_) => continue,
        };
        let result = if let Some(authority) = authority {
            serve_authority_connection(
                &mut connection,
                owner_uid,
                peer.uid,
                peer.pid,
                helper_epoch,
                authority,
            )
        } else {
            serve_staged_connection(&mut connection, owner_uid, peer.pid)
        };
        let _ = result;
    }
    Ok(())
}

fn serve_authority_connection(
    stream: &mut UnixStream,
    owner_uid: u32,
    observed_uid: u32,
    process_id: Option<u32>,
    helper_epoch: HelperEpoch,
    authority: RootEnrollmentAuthority,
) -> Result<(), HelperTransportError> {
    let ReceivedHelperRequest {
        request,
        descriptors,
    } = receive_request(stream)?;
    debug_assert!(descriptors.is_empty(), "handshake never carries material");
    let result = match request.op {
        HelperOp::Handshake(hello) => {
            let process_id = process_id.ok_or(HelperTransportError::PeerCredentials)?;
            let reservation = authority.reservation();
            let verified = verify_daemon_service(
                owner_uid,
                observed_uid,
                process_id,
                &hello.service,
                reservation,
            )
            .map_err(|_| HelperTransportError::PlatformIdentity)?;
            let root = verified_root_authority(verified, reservation)
                .map_err(|_| HelperTransportError::PlatformIdentity)?;
            if authority.is_enrolled() {
                return serve_enrolled_session(
                    stream,
                    request.id,
                    hello,
                    root,
                    helper_epoch,
                    PlatformLayout::current().ok_or(HelperTransportError::UnsupportedPlatform)?,
                );
            }
            let binding = HelperSessionBinding {
                authority_epoch: reservation.authority_epoch(),
                lease_id: reservation.lease_id(),
                helper_epoch,
            };
            negotiate_candidate(&hello, binding).map(HelperResult::Handshake)
        }
        HelperOp::Execute(_) => Err(HelperError::AuthenticationFailed),
    };
    let response = HelperResponse {
        id: request.id,
        result,
    };
    stream.write_all(&encode_response_frame(&response)?)?;
    stream.flush()?;
    Ok(())
}

fn serve_enrolled_session(
    stream: &mut UnixStream,
    request_id: u64,
    hello: super::protocol::HelperClientHello,
    root: RootAuthorityLedger,
    helper_epoch: HelperEpoch,
    layout: PlatformLayout,
) -> Result<(), HelperTransportError> {
    let mut session = open_observation_session(root, helper_epoch, layout)?;
    write_response(
        stream,
        &session.handle(HelperRequest {
            id: request_id,
            op: HelperOp::Handshake(hello),
        }),
    )?;
    loop {
        let ReceivedHelperRequest {
            request,
            descriptors,
        } = match receive_request(stream) {
            Ok(request) => request,
            Err(super::descriptor_transport::DescriptorTransportError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        // Observation-only enrollment advertises no material-bearing
        // capability. Exact descriptor count was already authenticated
        // against the operation; dropping here cannot enable an effect.
        drop(descriptors);
        write_response(stream, &session.handle(request))?;
    }
}

fn open_observation_session(
    root: RootAuthorityLedger,
    helper_epoch: HelperEpoch,
    layout: PlatformLayout,
) -> Result<
    EnrolledHelperSession<ProductionHelperExecutor, FsHelperLedgerStore>,
    HelperTransportError,
> {
    let executor = ProductionHelperExecutor::observation_only(layout, root.lease_id())
        .map_err(|_| HelperTransportError::SessionUnavailable)?;
    let mut store = FsHelperLedgerStore::root_owned(layout);
    let capabilities = vec![HelperCapability::Handshake, HelperCapability::Observe];
    match store.load() {
        Ok(ledger) => EnrolledHelperSession::recover_restricted(
            root,
            helper_epoch,
            ledger,
            executor,
            store,
            capabilities,
        )
        .map_err(|_| HelperTransportError::SessionUnavailable),
        Err(super::replay_store::HelperLedgerStoreError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            let baseline = root
                .unused_replay_baseline(&root.principal(), helper_epoch)
                .map_err(|_| HelperTransportError::SessionUnavailable)?;
            store
                .initialize(baseline.clone())
                .map_err(|_| HelperTransportError::SessionUnavailable)?;
            EnrolledHelperSession::resume_restricted(
                root,
                helper_epoch,
                baseline,
                executor,
                store,
                capabilities,
            )
            .map_err(|_| HelperTransportError::SessionUnavailable)
        }
        Err(_) => Err(HelperTransportError::SessionUnavailable),
    }
}

fn write_response(
    stream: &mut UnixStream,
    response: &HelperResponse,
) -> Result<(), HelperTransportError> {
    stream.write_all(&encode_response_frame(response)?)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
fn negotiate_verified_authority(
    hello: &super::protocol::HelperClientHello,
    verified: PlatformVerifiedAuthority,
    reservation: super::enrollment_store::AuthorityReservation,
    helper_epoch: HelperEpoch,
    enrolled: bool,
) -> Result<HelperResult, HelperError> {
    let _root = verified_root_authority(verified, reservation)?;
    let binding = HelperSessionBinding {
        authority_epoch: reservation.authority_epoch(),
        lease_id: reservation.lease_id(),
        helper_epoch,
    };
    if enrolled {
        negotiate_enrolled(hello, binding, &STAGED_CAPABILITIES).map(HelperResult::Handshake)
    } else {
        negotiate_candidate(hello, binding).map(HelperResult::Handshake)
    }
}

fn verified_root_authority(
    verified: PlatformVerifiedAuthority,
    reservation: super::enrollment_store::AuthorityReservation,
) -> Result<RootAuthorityLedger, HelperError> {
    RootAuthorityLedger::from_platform_verified(
        verified,
        reservation.boot_scope(),
        reservation.authority_epoch(),
        reservation.lease_id(),
    )
    .map_err(|_| HelperError::AuthenticationFailed)
}

fn random_helper_epoch() -> Result<HelperEpoch, HelperTransportError> {
    let mut source = File::open("/dev/urandom")?;
    for _ in 0..8 {
        let mut bytes = [0_u8; 8];
        source.read_exact(&mut bytes)?;
        if let Ok(epoch) = HelperEpoch::new(u64::from_be_bytes(bytes)) {
            return Ok(epoch);
        }
    }
    Err(HelperTransportError::Randomness)
}

fn serve_staged_connection(
    stream: &mut UnixStream,
    owner_uid: u32,
    peer_pid: Option<u32>,
) -> Result<(), HelperTransportError> {
    let ReceivedHelperRequest {
        request,
        descriptors,
    } = receive_request(stream)?;
    debug_assert!(descriptors.is_empty(), "handshake never carries material");
    let result = match request.op {
        HelperOp::Handshake(hello)
            if hello.owner_uid == owner_uid
                && peer_pid.is_none_or(|pid| hello.service.pid() == pid) =>
        {
            negotiate_staged(&hello).map(HelperResult::Handshake)
        }
        HelperOp::Handshake(_) => Err(HelperError::AuthenticationFailed),
        HelperOp::Execute(_) => Err(HelperError::NotEnrolled),
    };
    let response = HelperResponse {
        id: request.id,
        result,
    };
    stream.write_all(&encode_response_frame(&response)?)?;
    stream.flush()?;
    Ok(())
}

fn ensure_runtime_root(path: &Path) -> Result<(), HelperTransportError> {
    let created = match std::fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    if created {
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(HELPER_SOCKET_DIR_MODE),
        )?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != HELPER_SOCKET_DIR_MODE
    {
        return Err(HelperTransportError::UnsafeRuntimeRoot);
    }
    Ok(())
}

fn remove_stale_socket(path: &Path, owner_uid: u32) -> Result<(), HelperTransportError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != HELPER_SOCKET_MODE
    {
        return Err(HelperTransportError::UnsafeSocket);
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn chown_socket(path: &Path, owner_uid: u32) -> Result<(), HelperTransportError> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| HelperTransportError::UnsafeSocket)?;
    if unsafe { libc::chown(path.as_ptr(), owner_uid, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn validate_socket(path: &Path, owner_uid: u32) -> Result<(), HelperTransportError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != HELPER_SOCKET_MODE
    {
        return Err(HelperTransportError::UnsafeSocket);
    }
    Ok(())
}

struct PeerCredentials {
    uid: u32,
    pid: Option<u32>,
}

#[cfg(target_os = "linux")] // xtask:allow-platform-cfg: SO_PEERCRED is the Linux kernel authentication primitive
fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, HelperTransportError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd as _;

    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
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
        return Err(HelperTransportError::PeerCredentials);
    }
    let credentials = unsafe { credentials.assume_init() };
    Ok(PeerCredentials {
        uid: credentials.uid,
        pid: u32::try_from(credentials.pid).ok().filter(|pid| *pid != 0),
    })
}

#[cfg(target_os = "macos")] // xtask:allow-platform-cfg: getpeereid is the macOS kernel authentication primitive
fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, HelperTransportError> {
    use std::os::fd::AsRawFd as _;

    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) } != 0 {
        return Err(HelperTransportError::PeerCredentials);
    }
    Ok(PeerCredentials { uid, pid: None })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))] // xtask:allow-platform-cfg: unsupported Unix targets cannot authenticate helper peers
fn peer_credentials(_stream: &UnixStream) -> Result<PeerCredentials, HelperTransportError> {
    Err(HelperTransportError::UnsupportedPlatform)
}

#[derive(Debug, Error)]
pub enum HelperTransportError {
    #[error("the privileged helper must run as root")]
    RequiresRoot,
    #[error("this operating system has no authenticated helper transport")]
    UnsupportedPlatform,
    #[error("root enrollment state is unavailable")]
    EnrollmentUnavailable,
    #[error("the helper runtime root is not safe")]
    UnsafeRuntimeRoot,
    #[error("the helper socket is not the exact enrolled-owner socket")]
    UnsafeSocket,
    #[error("the helper peer credentials could not be authenticated")]
    PeerCredentials,
    #[error("the helper request exceeds its fixed frame size")]
    FrameTooLarge,
    #[error("the helper request is malformed")]
    MalformedRequest,
    #[error("the helper could not establish a fresh process incarnation")]
    Randomness,
    #[error("the enrolled helper session or replay ledger is unavailable")]
    SessionUnavailable,
    #[error("the daemon service identity was not verified")]
    PlatformIdentity,
    #[error("the helper response could not be encoded: {0}")]
    Frame(#[from] crate::vortix_core::ipc::FrameError),
    #[error("helper descriptor transport failed")]
    Descriptor,
    #[error("helper transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl From<super::descriptor_transport::DescriptorTransportError> for HelperTransportError {
    fn from(_: super::descriptor_transport::DescriptorTransportError) -> Self {
        Self::Descriptor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::protocol::{
        decode_response_frame, encode_request_frame, HelperCapability, HelperClientHello,
    };
    use crate::helper::validate::{verify_service_instance, VerifiedServiceFacts};
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, HelperEpoch, LeaseId, OperationDigest, PrivilegedOperation, PrivilegedRequest,
        RequestSequence, RootAuthorityLedger, ServiceInstanceClaim, ServiceManager,
    };

    fn hello(pid: u32, owner_uid: u32) -> HelperClientHello {
        HelperClientHello::current(
            owner_uid,
            ServiceInstanceClaim::systemd(pid, 9, OperationDigest::of_bytes(b"daemon"), [7; 32])
                .unwrap(),
            vec![HelperCapability::Handshake],
        )
    }

    fn verified(uid: u32, pid: u32) -> PlatformVerifiedAuthority {
        let digest = OperationDigest::of_bytes(b"daemon");
        let claim = ServiceInstanceClaim::systemd(pid, 9, digest, [7; 32]).unwrap();
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Systemd,
            uid,
            pid,
            9,
            digest,
            [7; 32],
            true,
            true,
        );
        verify_service_instance(uid, &claim, &facts).unwrap()
    }

    fn exchange(request: &HelperRequest, owner_uid: u32, peer_pid: Option<u32>) -> HelperResponse {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(&encode_request_frame(request).unwrap())
            .unwrap();
        serve_staged_connection(&mut server, owner_uid, peer_pid).unwrap();
        drop(server);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        decode_response_frame(&bytes).unwrap().unwrap().0
    }

    #[test]
    fn staged_transport_authenticates_owner_and_peer_pid() {
        let uid = 501;
        let response = exchange(
            &HelperRequest {
                id: 4,
                op: HelperOp::Handshake(hello(42, uid)),
            },
            uid,
            Some(42),
        );
        assert!(matches!(response.result, Ok(HelperResult::Handshake(_))));

        let wrong_pid = exchange(
            &HelperRequest {
                id: 5,
                op: HelperOp::Handshake(hello(42, uid)),
            },
            uid,
            Some(43),
        );
        assert!(matches!(
            wrong_pid.result,
            Err(HelperError::AuthenticationFailed)
        ));
    }

    #[test]
    fn staged_transport_rejects_every_execution_request() {
        let uid = 501;
        let digest = OperationDigest::of_bytes(b"daemon");
        let claim = ServiceInstanceClaim::systemd(42, 9, digest, [7; 32]).unwrap();
        let facts = VerifiedServiceFacts::from_os_verifier(
            ServiceManager::Systemd,
            uid,
            42,
            9,
            digest,
            [7; 32],
            true,
            true,
        );
        let verified = verify_service_instance(uid, &claim, &facts).unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([1; 16]),
            AuthorityEpoch(1),
            LeaseId::new([2; 32]),
        )
        .unwrap();
        let request = PrivilegedRequest::new(
            &root.principal(),
            HelperEpoch::new(1).unwrap(),
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::Observe(Vec::new()),
        )
        .unwrap();
        let request = HelperRequest {
            id: 9,
            op: HelperOp::Execute(Box::new(request)),
        };
        let response = exchange(&request, uid, None);
        assert!(matches!(response.result, Err(HelperError::NotEnrolled)));
    }

    #[test]
    fn verified_candidate_exposes_binding_but_no_execution_capability() {
        let uid = 501;
        let reservation = super::super::enrollment_store::AuthorityReservation::test_fixture(
            AuthorityEpoch(3),
            BootScope::new([4; 16]),
            LeaseId::new([5; 32]),
            [7; 32],
        );
        let candidate = negotiate_verified_authority(
            &hello(42, uid),
            verified(uid, 42),
            reservation,
            HelperEpoch::new(8).unwrap(),
            false,
        )
        .unwrap();
        let HelperResult::Handshake(candidate) = candidate else {
            panic!("expected helper handshake");
        };
        assert_eq!(
            candidate.authority_mode,
            super::super::protocol::HelperAuthorityMode::Candidate
        );
        assert_eq!(
            candidate.enabled_capabilities,
            vec![HelperCapability::Handshake]
        );
        assert_eq!(
            candidate.session.unwrap().authority_epoch,
            AuthorityEpoch(3)
        );

        let enrolled = negotiate_verified_authority(
            &hello(42, uid),
            verified(uid, 42),
            reservation,
            HelperEpoch::new(8).unwrap(),
            true,
        )
        .unwrap();
        let HelperResult::Handshake(enrolled) = enrolled else {
            panic!("expected helper handshake");
        };
        assert_eq!(
            enrolled.authority_mode,
            super::super::protocol::HelperAuthorityMode::Enrolled
        );
        assert_eq!(
            enrolled.enabled_capabilities,
            vec![HelperCapability::Handshake]
        );
    }
}
