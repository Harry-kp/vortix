//! Fixed Unix transport for the staged privileged helper.

#![allow(
    unsafe_code,
    reason = "Unix socket ownership, peer credentials, and creation umask require libc"
)]

use std::fs::File;
#[cfg(test)]
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use socket2::{Domain, SockAddr, Socket, Type};
use thiserror::Error;

use super::descriptor_transport::{receive_request, ReceivedHelperRequest};
use super::enrollment_store::{EnrollmentStoreError, RootEnrollmentAuthority, RootEnrollmentStore};
use super::executor::ProductionHelperExecutor;
use super::material::TunnelMaterialSet;
use super::platform_identity::{
    verify_daemon_service, verify_helper_service, PlatformIdentityError,
};
use super::protocol::{
    encode_response_frame, negotiate_candidate, negotiate_staged, HelperCapability, HelperError,
    HelperOp, HelperRequest, HelperResponse, HelperResult,
};
#[cfg(test)]
use super::protocol::{negotiate_enrolled, HelperSessionBinding, STAGED_CAPABILITIES};
use super::validate::{PlatformLayout, HELPER_SOCKET_DIR_MODE, HELPER_SOCKET_MODE};
use super::{replay_store::FsHelperLedgerStore, server::EnrolledHelperSession};
#[cfg(test)]
use crate::vortix_core::privileged::RequestSequence;
use crate::vortix_core::privileged::{HelperEpoch, PlatformVerifiedAuthority, RootAuthorityLedger};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn connect_verified_helper(
    owner_uid: u32,
    deadline: Instant,
) -> Result<(UnixStream, super::validate::VerifiedHelperPeer), HelperTransportError> {
    let layout = PlatformLayout::current().ok_or(HelperTransportError::UnsupportedPlatform)?;
    ensure_deadline(deadline)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    let address = SockAddr::unix(layout.helper_socket())?;
    match socket.connect(&address) {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
                || error.raw_os_error() == Some(libc::EINPROGRESS) =>
        {
            wait_connected(&socket, deadline)?;
        }
        Err(error) => return Err(error.into()),
    }
    ensure_deadline(deadline)?;
    socket.set_nonblocking(false)?;
    let stream: UnixStream = socket.into();
    let peer = verify_helper_service(&stream, owner_uid, layout, deadline).map_err(|error| {
        if matches!(error, PlatformIdentityError::DeadlineExpired) {
            HelperTransportError::DeadlineExpired
        } else {
            HelperTransportError::PlatformIdentity
        }
    })?;
    ensure_deadline(deadline)?;
    Ok((stream, peer))
}

fn ensure_deadline(deadline: Instant) -> Result<(), HelperTransportError> {
    if Instant::now() >= deadline {
        Err(HelperTransportError::DeadlineExpired)
    } else {
        Ok(())
    }
}

fn wait_connected(socket: &Socket, deadline: Instant) -> Result<(), HelperTransportError> {
    wait_writable(socket.as_raw_fd(), deadline)?;
    if let Some(error) = socket.take_error()? {
        return Err(error.into());
    }
    Ok(())
}

fn wait_writable(
    descriptor_fd: std::os::fd::RawFd,
    deadline: Instant,
) -> Result<(), HelperTransportError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(HelperTransportError::DeadlineExpired)?;
        let timeout = i32::try_from(
            remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128),
        )
        .expect("connect timeout is clamped to i32::MAX");
        let mut descriptor = libc::pollfd {
            fd: descriptor_fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if ready > 0 {
            ensure_deadline(deadline)?;
            return Ok(());
        }
        if ready == 0 {
            return Err(HelperTransportError::DeadlineExpired);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

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
            serve_authority_connection(&mut connection, owner_uid, peer.uid, peer.pid, authority)
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
                    PlatformLayout::current().ok_or(HelperTransportError::UnsupportedPlatform)?,
                );
            }
            negotiate_candidate(
                &hello,
                reservation.binding(),
                HelperEpoch::new(1).expect("one is a valid helper epoch"),
            )
            .map(HelperResult::Handshake)
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
    layout: PlatformLayout,
) -> Result<(), HelperTransportError> {
    let mut session = open_observation_session(root, layout)?;
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
        let materials = match &request.op {
            HelperOp::Execute(operation)
                if matches!(
                    operation.operation(),
                    crate::vortix_core::privileged::PrivilegedOperation::StartTunnel(_)
                ) =>
            {
                let crate::vortix_core::privileged::PrivilegedOperation::StartTunnel(plan) =
                    operation.operation()
                else {
                    unreachable!("guard and extraction use the same operation")
                };
                Some(
                    TunnelMaterialSet::for_plan(plan, descriptors)
                        .map_err(|_| HelperTransportError::Descriptor)?,
                )
            }
            _ => {
                debug_assert!(descriptors.is_empty());
                None
            }
        };
        write_response(stream, &session.handle_with_materials(request, materials))?;
    }
}

fn open_observation_session(
    root: RootAuthorityLedger,
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
        Ok(ledger) => {
            let (helper_epoch, _) = ledger
                .next_helper_session()
                .map_err(|_| HelperTransportError::SessionUnavailable)?;
            EnrolledHelperSession::recover_restricted(
                root,
                helper_epoch,
                ledger,
                executor,
                store,
                capabilities,
            )
            .map_err(|_| HelperTransportError::SessionUnavailable)
        }
        Err(super::replay_store::HelperLedgerStoreError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound =>
        {
            let helper_epoch =
                HelperEpoch::new(1).map_err(|_| HelperTransportError::SessionUnavailable)?;
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
    if enrolled {
        negotiate_enrolled(
            hello,
            reservation.binding(),
            helper_epoch,
            RequestSequence::new(1).expect("one is a valid request sequence"),
            &STAGED_CAPABILITIES,
        )
        .map(HelperResult::Handshake)
    } else {
        negotiate_candidate(hello, reservation.binding(), helper_epoch).map(HelperResult::Handshake)
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
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| HelperTransportError::PeerCredentials)?;
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
    #[error("the enrolled helper session or replay ledger is unavailable")]
    SessionUnavailable,
    #[error("the helper/daemon service identity was not verified")]
    PlatformIdentity,
    #[error("the helper connection or identity deadline expired")]
    DeadlineExpired,
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
    use crate::daemon::helper_client::{
        AuthenticatedHelperTransport, HelperConnectBudget, SharedAuthenticatedHelper,
    };
    use crate::helper::protocol::{
        decode_response_frame, encode_request_frame, HelperCapability, HelperClientHello,
    };
    use crate::helper::validate::{
        verify_helper_peer, verify_service_instance, ArtifactFact, HelperPeerFacts,
        InstallManifest, VerifiedServiceFacts,
    };
    use crate::helper::HelperServerHello;
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        AuthorityBinding, BootScope, HelperEpoch, LeaseId, OperationDigest, PrivilegedOperation,
        PrivilegedRequest, ProtocolPlan, ReceiptLedger, RejectionCode, RequestSequence,
        RootAuthorityLedger, ServiceInstanceClaim, ServiceManager, WireGuardInterfaceOptions,
        WireGuardPeerPlan, WireGuardPlan,
    };
    use crate::vortix_core::profile::ProfileId;
    use std::io::{Seek as _, SeekFrom};
    use std::time::Instant;

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

    fn authority_fixture() -> (RootAuthorityLedger, AuthorityBinding, ServiceInstanceClaim) {
        let owner_uid = 501;
        let authority_epoch = AuthorityEpoch(3);
        let boot_scope = BootScope::new([4; 16]);
        let lease_id = LeaseId::new([5; 32]);
        let service =
            ServiceInstanceClaim::systemd(42, 9, OperationDigest::of_bytes(b"daemon"), [7; 32])
                .unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified(owner_uid, service.pid()),
            boot_scope,
            authority_epoch,
            lease_id,
        )
        .unwrap();
        let binding =
            AuthorityBinding::for_service(authority_epoch, boot_scope, lease_id, &service).unwrap();
        (root, binding, service)
    }

    fn verified_helper_peer() -> super::super::validate::VerifiedHelperPeer {
        let digest = OperationDigest::of_bytes(b"helper");
        let manifest = InstallManifest::new(
            "0.4.3".into(),
            1,
            OperationDigest::of_bytes(b"daemon"),
            digest,
            OperationDigest::of_bytes(b"bootstrap"),
            None,
        )
        .unwrap();
        let artifact = ArtifactFact::from_os_verifier(
            super::super::ArtifactKind::Helper,
            std::path::PathBuf::from(PlatformLayout::Linux.helper_path()),
            0,
            0o755,
            digest,
            false,
        );
        let facts = HelperPeerFacts::from_os_verifier(
            0,
            77,
            91,
            std::path::PathBuf::from(PlatformLayout::Linux.helper_socket()),
            501,
            super::super::HELPER_SOCKET_MODE,
            artifact,
        );
        verify_helper_peer(501, PlatformLayout::Linux, &manifest, &facts).unwrap()
    }

    fn read_request(stream: &mut UnixStream) -> HelperRequest {
        receive_request(stream).unwrap().request
    }

    fn enrolled_hello(
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        next_sequence: RequestSequence,
        enabled_capabilities: Vec<HelperCapability>,
    ) -> HelperServerHello {
        HelperServerHello {
            product: "vortix-helper".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            protocol: super::super::HELPER_PROTOCOL_MAX,
            schema: super::super::HELPER_SCHEMA_MAX,
            authority_mode: super::super::HelperAuthorityMode::Enrolled,
            contract_capabilities: super::super::protocol::CONTRACT_CAPABILITIES.to_vec(),
            enabled_capabilities,
            session: Some(HelperSessionBinding::v4(
                authority,
                helper_epoch,
                next_sequence,
            )),
        }
    }

    fn accept_handshake(
        stream: &mut UnixStream,
        authority: AuthorityBinding,
        helper_epoch: HelperEpoch,
        enabled_capabilities: Vec<HelperCapability>,
    ) {
        let handshake = read_request(stream);
        assert_eq!(handshake.id, 1);
        write_response(
            stream,
            &HelperResponse {
                id: handshake.id,
                result: Ok(HelperResult::Handshake(enrolled_hello(
                    authority,
                    helper_epoch,
                    RequestSequence::new(1).unwrap(),
                    enabled_capabilities,
                ))),
            },
        )
        .unwrap();
    }

    fn rejected_response(
        root: &RootAuthorityLedger,
        request: &PrivilegedRequest,
        response_id: u64,
    ) -> HelperResponse {
        let principal = root.principal();
        let receipt = ReceiptLedger::new(root, &principal)
            .unwrap()
            .rejected(request, RejectionCode::InvalidPlan)
            .unwrap();
        HelperResponse {
            id: response_id,
            result: Ok(HelperResult::Receipt(
                serde_json::to_value(receipt).unwrap(),
            )),
        }
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
    fn verified_connect_rejects_an_expired_absolute_deadline_before_socket_work() {
        assert!(matches!(
            connect_verified_helper(501, Instant::now()),
            Err(HelperTransportError::DeadlineExpired)
        ));
    }

    #[test]
    fn nonblocking_connect_wait_honors_deadline_when_socket_is_saturated() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let payload = [0_u8; 8 * 1024];
        loop {
            match writer.write(&payload) {
                Ok(0) => panic!("Unix socket accepted no bytes before saturation"),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("failed to saturate Unix socket: {error}"),
            }
        }
        assert!(matches!(
            wait_writable(
                writer.as_raw_fd(),
                Instant::now() + Duration::from_millis(5)
            ),
            Err(HelperTransportError::DeadlineExpired)
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
            candidate.session.unwrap().authority_epoch(),
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

    #[test]
    fn authenticated_transport_handshakes_and_verifies_strictly_sequenced_receipts() {
        let (root, authority, service) = authority_fixture();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            accept_handshake(
                &mut server_stream,
                authority,
                helper_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            for expected in 1..=2 {
                let execution = read_request(&mut server_stream);
                assert_eq!(execution.id, expected + 1);
                let HelperOp::Execute(request) = execution.op else {
                    panic!("expected typed helper execution request");
                };
                assert_eq!(request.sequence(), RequestSequence::new(expected).unwrap());
                write_response(
                    &mut server_stream,
                    &rejected_response(&root, &request, execution.id),
                )
                .unwrap();
            }
        });

        let mut transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        assert_eq!(transport.authority_binding(), authority);
        for _ in 0..2 {
            let receipt = transport
                .execute(
                    PrivilegedOperation::Observe(Vec::new()),
                    &[],
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap();
            assert!(receipt.is_rejected());
        }
        server.join().unwrap();
    }

    #[test]
    fn shared_authenticated_helper_serializes_one_exact_authority_sequence() {
        let (root, authority, service) = authority_fixture();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            accept_handshake(
                &mut server_stream,
                authority,
                helper_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            for expected in 1..=2 {
                let execution = read_request(&mut server_stream);
                let HelperOp::Execute(request) = execution.op else {
                    panic!("expected typed helper execution request");
                };
                assert_eq!(request.sequence(), RequestSequence::new(expected).unwrap());
                write_response(
                    &mut server_stream,
                    &rejected_response(&root, &request, execution.id),
                )
                .unwrap();
            }
        });
        let transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        let helper = std::sync::Arc::new(SharedAuthenticatedHelper::new(transport));
        assert_eq!(helper.authority_binding(), authority);
        assert!(helper.enables(HelperCapability::Observe));
        assert!(!helper.enables(HelperCapability::TunnelLifecycle));
        let calls = (0..2)
            .map(|_| {
                let helper = std::sync::Arc::clone(&helper);
                std::thread::spawn(move || {
                    helper
                        .execute(
                            PrivilegedOperation::Observe(Vec::new()),
                            &[],
                            Instant::now() + Duration::from_secs(1),
                        )
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        for call in calls {
            assert!(call.join().unwrap().is_rejected());
        }
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_carries_only_descriptors_declared_by_typed_plan() {
        let (root, authority, service) = authority_fixture();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            accept_handshake(
                &mut server_stream,
                authority,
                helper_epoch,
                vec![
                    HelperCapability::Handshake,
                    HelperCapability::Observe,
                    HelperCapability::TunnelLifecycle,
                ],
            );
            let received = receive_request(&server_stream).unwrap();
            assert_eq!(received.descriptors.len(), 1);
            let request_id = received.request.id;
            let HelperOp::Execute(request) = received.request.op else {
                panic!("expected tunnel execution");
            };
            let mut material = String::new();
            let mut received_descriptor = &received.descriptors[0];
            received_descriptor.read_to_string(&mut material).unwrap();
            assert_eq!(material, "private-key");
            write_response(
                &mut server_stream,
                &rejected_response(&root, &request, request_id),
            )
            .unwrap();
        });
        let plan = WireGuardPlan::new(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            1,
            Vec::new(),
            vec![WireGuardPeerPlan::new([2; 32], None, Vec::new(), None).unwrap()],
            WireGuardInterfaceOptions::default(),
        )
        .unwrap();
        let mut descriptor = tempfile::tempfile().unwrap();
        descriptor.write_all(b"private-key").unwrap();
        descriptor.seek(SeekFrom::Start(0)).unwrap();
        let mut transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[
                HelperCapability::Handshake,
                HelperCapability::Observe,
                HelperCapability::TunnelLifecycle,
            ],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        assert!(transport
            .execute(
                PrivilegedOperation::StartTunnel(ProtocolPlan::WireGuard(plan)),
                &[descriptor.as_raw_fd()],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
            .is_rejected());
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_rejects_authority_and_capability_mismatch() {
        for capability_mismatch in [false, true] {
            let (_root, authority, service) = authority_fixture();
            let helper_epoch = HelperEpoch::new(8).unwrap();
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let advertised_authority = if capability_mismatch {
                authority
            } else {
                AuthorityBinding::new(
                    authority.authority_epoch(),
                    authority.boot_scope(),
                    authority.lease_id(),
                    OperationDigest::of_bytes(b"wrong service instance"),
                )
                .unwrap()
            };
            let enabled = vec![HelperCapability::Handshake, HelperCapability::Observe];
            let server = std::thread::spawn(move || {
                accept_handshake(
                    &mut server_stream,
                    advertised_authority,
                    helper_epoch,
                    enabled,
                );
            });
            let required = if capability_mismatch {
                vec![
                    HelperCapability::Handshake,
                    HelperCapability::Observe,
                    HelperCapability::TunnelLifecycle,
                ]
            } else {
                vec![HelperCapability::Handshake, HelperCapability::Observe]
            };
            let error = AuthenticatedHelperTransport::open_verified(
                client_stream,
                &verified_helper_peer(),
                501,
                authority,
                &service,
                &required,
                HelperConnectBudget::new(
                    RequestSequence::new(1).unwrap(),
                    Instant::now() + Duration::from_secs(1),
                ),
            )
            .err()
            .unwrap();
            if capability_mismatch {
                assert!(
                    matches!(
                        error,
                        crate::daemon::helper_client::HelperClientError::CapabilityMismatch
                    ),
                    "unexpected capability error: {error:?}"
                );
            } else {
                assert!(
                    matches!(
                        error,
                        crate::daemon::helper_client::HelperClientError::AuthorityMismatch
                    ),
                    "unexpected authority error: {error:?}"
                );
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn authenticated_transport_rejects_v3_authority_mismatch_at_response_boundary() {
        let (_root, authority, service) = authority_fixture();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let handshake = read_request(&mut server_stream);
            write_response(
                &mut server_stream,
                &HelperResponse {
                    id: handshake.id,
                    result: Ok(HelperResult::Handshake(HelperServerHello {
                        product: "vortix-helper".into(),
                        product_version: env!("CARGO_PKG_VERSION").into(),
                        protocol: super::super::HELPER_PROTOCOL_MAX,
                        schema: 3,
                        authority_mode: super::super::HelperAuthorityMode::Enrolled,
                        contract_capabilities: super::super::protocol::CONTRACT_CAPABILITIES
                            .to_vec(),
                        enabled_capabilities: vec![
                            HelperCapability::Handshake,
                            HelperCapability::Observe,
                        ],
                        session: Some(HelperSessionBinding::v3(
                            AuthorityEpoch(99),
                            authority.lease_id(),
                            HelperEpoch::new(8).unwrap(),
                        )),
                    })),
                },
            )
            .unwrap();
        });
        let error = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            crate::daemon::helper_client::HelperClientError::AuthorityMismatch
        ));
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_accepts_exact_v3_overlap_before_commands() {
        let (_root, authority, service) = authority_fixture();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let handshake = read_request(&mut server_stream);
            write_response(
                &mut server_stream,
                &HelperResponse {
                    id: handshake.id,
                    result: Ok(HelperResult::Handshake(HelperServerHello {
                        product: "vortix-helper".into(),
                        product_version: env!("CARGO_PKG_VERSION").into(),
                        protocol: super::super::HELPER_PROTOCOL_MAX,
                        schema: 3,
                        authority_mode: super::super::HelperAuthorityMode::Enrolled,
                        contract_capabilities: super::super::protocol::CONTRACT_CAPABILITIES
                            .to_vec(),
                        enabled_capabilities: vec![
                            HelperCapability::Handshake,
                            HelperCapability::Observe,
                        ],
                        session: Some(HelperSessionBinding::v3(
                            authority.authority_epoch(),
                            authority.lease_id(),
                            HelperEpoch::new(8).unwrap(),
                        )),
                    })),
                },
            )
            .unwrap();
        });
        let transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(11).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        assert_eq!(
            transport.reconnect_floor(),
            RequestSequence::new(11).unwrap()
        );
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_rejects_response_and_replay_identity_mismatch() {
        for replay_mismatch in [false, true] {
            let (root, authority, service) = authority_fixture();
            let helper_epoch = HelperEpoch::new(8).unwrap();
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                accept_handshake(
                    &mut server_stream,
                    authority,
                    helper_epoch,
                    vec![HelperCapability::Handshake, HelperCapability::Observe],
                );
                let execution = read_request(&mut server_stream);
                let HelperOp::Execute(request) = execution.op else {
                    panic!("expected typed helper execution request");
                };
                let response = if replay_mismatch {
                    let wrong = PrivilegedRequest::new(
                        &root.principal(),
                        helper_epoch,
                        RequestSequence::new(2).unwrap(),
                        request.operation().clone(),
                    )
                    .unwrap();
                    rejected_response(&root, &wrong, execution.id)
                } else {
                    rejected_response(&root, &request, execution.id + 1)
                };
                write_response(&mut server_stream, &response).unwrap();
            });
            let mut transport = AuthenticatedHelperTransport::open_verified(
                client_stream,
                &verified_helper_peer(),
                501,
                authority,
                &service,
                &[HelperCapability::Handshake, HelperCapability::Observe],
                HelperConnectBudget::new(
                    RequestSequence::new(1).unwrap(),
                    Instant::now() + Duration::from_secs(1),
                ),
            )
            .unwrap();
            let error = transport
                .execute(
                    PrivilegedOperation::Observe(Vec::new()),
                    &[],
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err();
            assert_eq!(
                error.recovery(),
                crate::daemon::helper_client::RecoveryAction::ReconcileRequired
            );
            if replay_mismatch {
                assert!(matches!(
                    error.source(),
                    crate::daemon::helper_client::HelperClientError::Receipt(_)
                ));
            } else {
                assert!(
                    matches!(
                        error.source(),
                        crate::daemon::helper_client::HelperClientError::ResponseIdMismatch
                    ),
                    "unexpected response ID error: {error:?}"
                );
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn authenticated_transport_distinguishes_pre_send_timeout_from_post_send_loss() {
        let (_root, authority, service) = authority_fixture();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            accept_handshake(
                &mut server_stream,
                authority,
                helper_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            let execution = read_request(&mut server_stream);
            let HelperOp::Execute(request) = execution.op else {
                panic!("expected typed helper execution request");
            };
            assert_eq!(request.sequence(), RequestSequence::new(1).unwrap());
        });
        let mut transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        let before_send = transport
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now(),
            )
            .unwrap_err();
        assert_eq!(
            before_send.recovery(),
            crate::daemon::helper_client::RecoveryAction::Unavailable
        );
        let after_send = transport
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(
            after_send.recovery(),
            crate::daemon::helper_client::RecoveryAction::ReconcileRequired
        );
        let poisoned = transport
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(
            poisoned.recovery(),
            crate::daemon::helper_client::RecoveryAction::ReconcileRequired
        );
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_bounds_and_strictly_decodes_responses() {
        for oversized in [false, true] {
            let (_root, authority, service) = authority_fixture();
            let helper_epoch = HelperEpoch::new(8).unwrap();
            let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                accept_handshake(
                    &mut server_stream,
                    authority,
                    helper_epoch,
                    vec![HelperCapability::Handshake, HelperCapability::Observe],
                );
                let _ = read_request(&mut server_stream);
                let prefix = if oversized {
                    u32::try_from(super::super::MAX_HELPER_FRAME_BYTES + 1)
                        .unwrap()
                        .to_be_bytes()
                } else {
                    1_u32.to_be_bytes()
                };
                server_stream.write_all(&prefix).unwrap();
                if !oversized {
                    server_stream.write_all(b"{").unwrap();
                }
            });
            let mut transport = AuthenticatedHelperTransport::open_verified(
                client_stream,
                &verified_helper_peer(),
                501,
                authority,
                &service,
                &[HelperCapability::Handshake, HelperCapability::Observe],
                HelperConnectBudget::new(
                    RequestSequence::new(1).unwrap(),
                    Instant::now() + Duration::from_secs(1),
                ),
            )
            .unwrap();
            let error = transport
                .execute(
                    PrivilegedOperation::Observe(Vec::new()),
                    &[],
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err();
            assert_eq!(
                error.recovery(),
                crate::daemon::helper_client::RecoveryAction::ReconcileRequired
            );
            assert!(if oversized {
                matches!(
                    error.source(),
                    crate::daemon::helper_client::HelperClientError::OversizedResponse
                )
            } else {
                matches!(
                    error.source(),
                    crate::daemon::helper_client::HelperClientError::MalformedResponse
                )
            });
            server.join().unwrap();
        }
    }

    #[test]
    fn authenticated_transport_keeps_pre_admission_helper_rejections_definitive() {
        let (root, authority, service) = authority_fixture();
        let helper_epoch = HelperEpoch::new(8).unwrap();
        let (client_stream, mut server_stream) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            accept_handshake(
                &mut server_stream,
                authority,
                helper_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            for error in [
                HelperError::CapabilityUnavailable {
                    capability: HelperCapability::Observe,
                },
                HelperError::AuthenticationFailed,
            ] {
                let execution = read_request(&mut server_stream);
                write_response(
                    &mut server_stream,
                    &HelperResponse {
                        id: execution.id,
                        result: Err(error),
                    },
                )
                .unwrap();
            }
            let execution = read_request(&mut server_stream);
            let HelperOp::Execute(request) = execution.op else {
                panic!("expected typed helper request");
            };
            assert_eq!(request.sequence(), RequestSequence::new(3).unwrap());
            write_response(
                &mut server_stream,
                &rejected_response(&root, &request, execution.id),
            )
            .unwrap();
        });
        let mut transport = AuthenticatedHelperTransport::open_verified(
            client_stream,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        for _ in 0..2 {
            let failure = transport
                .execute(
                    PrivilegedOperation::Observe(Vec::new()),
                    &[],
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err();
            assert_eq!(
                failure.recovery(),
                crate::daemon::helper_client::RecoveryAction::Unavailable
            );
            assert!(matches!(
                failure.source(),
                crate::daemon::helper_client::HelperClientError::Helper(_)
            ));
        }
        assert!(transport
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
            .is_rejected());
        server.join().unwrap();
    }

    #[test]
    fn authenticated_transport_reconnects_only_as_a_fresh_helper_session() {
        let (_root, authority, service) = authority_fixture();
        let first_epoch = HelperEpoch::new(8).unwrap();
        let (first_client, mut first_server) = UnixStream::pair().unwrap();
        let first = std::thread::spawn(move || {
            accept_handshake(
                &mut first_server,
                authority,
                first_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            let _ = read_request(&mut first_server);
        });
        let mut lost = AuthenticatedHelperTransport::open_verified(
            first_client,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                RequestSequence::new(1).unwrap(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        let error = lost
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert_eq!(
            error.recovery(),
            crate::daemon::helper_client::RecoveryAction::ReconcileRequired
        );
        first.join().unwrap();

        let (root, _, _) = authority_fixture();
        let second_epoch = HelperEpoch::new(9).unwrap();
        let (second_client, mut second_server) = UnixStream::pair().unwrap();
        let second = std::thread::spawn(move || {
            accept_handshake(
                &mut second_server,
                authority,
                second_epoch,
                vec![HelperCapability::Handshake, HelperCapability::Observe],
            );
            let execution = read_request(&mut second_server);
            let HelperOp::Execute(request) = execution.op else {
                panic!("expected reconciliation observation");
            };
            assert_eq!(request.helper_epoch(), second_epoch);
            assert_eq!(request.sequence(), RequestSequence::new(2).unwrap());
            write_response(
                &mut second_server,
                &rejected_response(&root, &request, execution.id),
            )
            .unwrap();
        });
        let mut reconnected = AuthenticatedHelperTransport::open_verified(
            second_client,
            &verified_helper_peer(),
            501,
            authority,
            &service,
            &[HelperCapability::Handshake, HelperCapability::Observe],
            HelperConnectBudget::new(
                lost.reconnect_floor(),
                Instant::now() + Duration::from_secs(1),
            ),
        )
        .unwrap();
        assert!(reconnected
            .execute(
                PrivilegedOperation::Observe(Vec::new()),
                &[],
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap()
            .is_rejected());
        second.join().unwrap();
    }
}
