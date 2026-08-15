//! Bounded helper frames with descriptor-only secret material.
//!
//! `SCM_RIGHTS` is local transport metadata, not part of the serialized helper
//! vocabulary. Descriptors are ordered exactly like `ProtocolPlan::descriptor_refs`
//! and are rejected for every operation that does not declare descriptors.

#![allow(
    unsafe_code,
    reason = "Unix ancillary descriptor transfer requires sendmsg/recvmsg"
)]

use std::fs::File;
use std::io::{ErrorKind, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream;

use thiserror::Error;

use super::protocol::{encode_request_frame, HelperOp, HelperRequest, MAX_HELPER_FRAME_BYTES};
use crate::vortix_core::privileged::PrivilegedOperation;

const MAX_FDS_PER_MESSAGE: usize = 64;
const MAX_TUNNEL_DESCRIPTORS: usize = 257;
const CONTROL_WORDS: usize = 64;

pub(crate) struct ReceivedHelperRequest {
    pub(crate) request: HelperRequest,
    pub(crate) descriptors: Vec<File>,
}

pub(crate) fn receive_request(
    stream: &UnixStream,
) -> Result<ReceivedHelperRequest, DescriptorTransportError> {
    let (frame, descriptors) = receive_frame(stream)?;
    let request: HelperRequest = serde_json::from_slice(&frame[4..])
        .map_err(|_| DescriptorTransportError::MalformedRequest)?;
    let expected = expected_descriptor_count(&request);
    if descriptors.len() != expected {
        return Err(DescriptorTransportError::DescriptorCountMismatch);
    }
    Ok(ReceivedHelperRequest {
        request,
        descriptors,
    })
}

#[allow(
    dead_code,
    reason = "daemon helper execution calls this after U12 capability cutover"
)]
pub(crate) fn send_request(
    stream: &mut UnixStream,
    request: &HelperRequest,
    descriptors: &[RawFd],
) -> Result<(), DescriptorTransportError> {
    if descriptors.len() != expected_descriptor_count(request) {
        return Err(DescriptorTransportError::DescriptorCountMismatch);
    }
    let frame = encode_request_frame(request)?;
    send_frame(stream, &frame, descriptors)
}

fn expected_descriptor_count(request: &HelperRequest) -> usize {
    match &request.op {
        HelperOp::Execute(boxed) => match boxed.operation() {
            PrivilegedOperation::StartTunnel(plan) => plan.descriptor_count(),
            _ => 0,
        },
        HelperOp::Handshake(_) => 0,
    }
}

fn receive_frame(stream: &UnixStream) -> Result<(Vec<u8>, Vec<File>), DescriptorTransportError> {
    let mut frame = vec![0_u8; MAX_HELPER_FRAME_BYTES + 4];
    let mut filled = 0_usize;
    let mut target = 4_usize;
    let mut descriptors = Vec::new();
    loop {
        let (received, mut batch) = receive_chunk(stream, &mut frame[filled..target])?;
        if received == 0 {
            return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "helper frame ended").into());
        }
        filled += received;
        descriptors.append(&mut batch);
        if descriptors.len() > MAX_TUNNEL_DESCRIPTORS {
            return Err(DescriptorTransportError::TooManyDescriptors);
        }
        if filled >= 4 && target == 4 {
            let body_len =
                u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
            if body_len > MAX_HELPER_FRAME_BYTES {
                return Err(DescriptorTransportError::FrameTooLarge);
            }
            target = 4 + body_len;
            if target == filled {
                break;
            }
        } else if filled == target {
            break;
        }
    }
    frame.truncate(target);
    Ok((frame, descriptors))
}

#[allow(
    clippy::cast_ptr_alignment,
    reason = "CMSG_DATA returns kernel-aligned SCM_RIGHTS storage despite its u8 pointer type"
)]
fn receive_chunk(
    stream: &UnixStream,
    output: &mut [u8],
) -> Result<(usize, Vec<File>), DescriptorTransportError> {
    let mut control = [0_usize; CONTROL_WORDS];
    let mut iovec = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let mut message = MaybeUninit::<libc::msghdr>::zeroed();
    let message = unsafe {
        let pointer = message.as_mut_ptr();
        (*pointer).msg_iov = &raw mut iovec;
        (*pointer).msg_iovlen = 1;
        (*pointer).msg_control = control.as_mut_ptr().cast();
        #[allow(
            clippy::useless_conversion,
            reason = "msghdr.msg_controllen is usize on Linux and socklen_t on macOS"
        )]
        {
            (*pointer).msg_controllen = std::mem::size_of_val(&control)
                .try_into()
                .map_err(|_| DescriptorTransportError::TruncatedControl)?;
        }
        &mut *pointer
    };
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), message, 0) };
    if received < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(DescriptorTransportError::TruncatedControl);
    }

    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let current = unsafe { &*header };
        if current.cmsg_level != libc::SOL_SOCKET || current.cmsg_type != libc::SCM_RIGHTS {
            return Err(DescriptorTransportError::UnexpectedControl);
        }
        let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
        let current_len = current.cmsg_len as usize;
        if current_len < header_len
            || (current_len - header_len) % std::mem::size_of::<RawFd>() != 0
        {
            return Err(DescriptorTransportError::TruncatedControl);
        }
        let count = (current_len - header_len) / std::mem::size_of::<RawFd>();
        let data = unsafe { libc::CMSG_DATA(header).cast::<RawFd>() };
        for index in 0..count {
            let descriptor = unsafe { *data.add(index) };
            if descriptor < 0
                || unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
            {
                if descriptor >= 0 {
                    unsafe { libc::close(descriptor) };
                }
                return Err(DescriptorTransportError::InvalidDescriptor);
            }
            descriptors.push(unsafe { File::from_raw_fd(descriptor) });
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok((
        usize::try_from(received).map_err(|_| DescriptorTransportError::InvalidDescriptor)?,
        descriptors,
    ))
}

fn send_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    descriptors: &[RawFd],
) -> Result<(), DescriptorTransportError> {
    if descriptors.len() > MAX_TUNNEL_DESCRIPTORS {
        return Err(DescriptorTransportError::TooManyDescriptors);
    }
    if descriptors.is_empty() {
        stream.write_all(frame)?;
        return Ok(());
    }
    let chunks = descriptors.chunks(MAX_FDS_PER_MESSAGE).collect::<Vec<_>>();
    if frame.len() < chunks.len() {
        return Err(DescriptorTransportError::MalformedRequest);
    }
    for (index, chunk) in chunks.iter().enumerate() {
        send_chunk(stream, &frame[index..=index], chunk)?;
    }
    stream.write_all(&frame[chunks.len()..])?;
    Ok(())
}

#[allow(
    clippy::cast_ptr_alignment,
    reason = "CMSG_DATA returns kernel-aligned SCM_RIGHTS storage despite its u8 pointer type"
)]
fn send_chunk(
    stream: &UnixStream,
    bytes: &[u8],
    descriptors: &[RawFd],
) -> Result<(), DescriptorTransportError> {
    let mut control = [0_usize; CONTROL_WORDS];
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message = MaybeUninit::<libc::msghdr>::zeroed();
    let message = unsafe {
        let pointer = message.as_mut_ptr();
        (*pointer).msg_iov = &raw mut iovec;
        (*pointer).msg_iovlen = 1;
        (*pointer).msg_control = control.as_mut_ptr().cast();
        let descriptor_bytes = libc::c_uint::try_from(std::mem::size_of_val(descriptors))
            .map_err(|_| DescriptorTransportError::TooManyDescriptors)?;
        (*pointer).msg_controllen = libc::CMSG_SPACE(descriptor_bytes) as _;
        let header = libc::CMSG_FIRSTHDR(&raw const *pointer);
        if header.is_null() {
            return Err(DescriptorTransportError::TruncatedControl);
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes) as _;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            descriptors.len(),
        );
        &mut *pointer
    };
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), message, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if usize::try_from(sent).map_err(|_| DescriptorTransportError::ShortWrite)? != bytes.len() {
        return Err(DescriptorTransportError::ShortWrite);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub(crate) enum DescriptorTransportError {
    #[error("helper descriptor frame is too large")]
    FrameTooLarge,
    #[error("helper request is malformed")]
    MalformedRequest,
    #[error("helper tunnel descriptor count does not match the canonical plan")]
    DescriptorCountMismatch,
    #[error("helper request carries too many tunnel descriptors")]
    TooManyDescriptors,
    #[error("helper ancillary control data was truncated")]
    TruncatedControl,
    #[error("helper request contains unexpected ancillary control data")]
    UnexpectedControl,
    #[error("helper received an invalid descriptor")]
    InvalidDescriptor,
    #[error("helper descriptor frame was only partially written")]
    ShortWrite,
    #[error("helper descriptor transport frame could not be encoded")]
    Frame(#[from] crate::vortix_core::ipc::FrameError),
    #[error("helper descriptor transport I/O failed")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::protocol::{HelperCapability, HelperClientHello};
    use crate::vortix_core::control::AuthorityEpoch;
    use crate::vortix_core::privileged::{
        BootScope, HelperEpoch, LeaseId, OpenVpnAuthFactors, OpenVpnPlan, OpenVpnRemote,
        OpenVpnRemoteSelection, OpenVpnTransport, OperationDigest, PeerProcessIdentity,
        PlatformVerifiedAuthority, ProtocolPlan, RequestSequence, RootAuthorityLedger,
        ServiceInstanceClaim, WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPlan,
    };
    use crate::vortix_core::profile::ProfileId;
    use std::io::{Read as _, Seek as _, SeekFrom};

    fn handshake() -> HelperRequest {
        HelperRequest {
            id: 1,
            op: HelperOp::Handshake(HelperClientHello::current(
                501,
                ServiceInstanceClaim::systemd(42, 7, OperationDigest::of_bytes(b"daemon"), [9; 32])
                    .unwrap(),
                vec![HelperCapability::Handshake],
            )),
        }
    }

    fn wireguard_request() -> HelperRequest {
        let plan = WireGuardPlan::new(
            ProfileId::parse("a".repeat(ProfileId::HEX_LEN)).unwrap(),
            1,
            Vec::new(),
            vec![WireGuardPeerPlan::new([2; 32], None, Vec::new(), None).unwrap()],
            WireGuardInterfaceOptions::default(),
        )
        .unwrap();
        start_request(ProtocolPlan::WireGuard(plan))
    }

    fn interactive_openvpn_request() -> HelperRequest {
        let plan = OpenVpnPlan::new(
            ProfileId::parse("b".repeat(ProfileId::HEX_LEN)).unwrap(),
            1,
            vec![OpenVpnRemote::dns("vpn.example.com", 1194, OpenVpnTransport::Udp).unwrap()],
            OpenVpnRemoteSelection::Ordered,
            OpenVpnAuthFactors::username_password(),
            Vec::new(),
        )
        .unwrap();
        start_request(ProtocolPlan::OpenVpn(plan))
    }

    fn start_request(plan: ProtocolPlan) -> HelperRequest {
        let claim =
            ServiceInstanceClaim::systemd(42, 7, OperationDigest::of_bytes(b"daemon"), [9; 32])
                .unwrap();
        let peer = PeerProcessIdentity::untrusted_claim(501, 42, 7).unwrap();
        let verified =
            PlatformVerifiedAuthority::from_platform_verifier(501, peer, &claim).unwrap();
        let root = RootAuthorityLedger::from_platform_verified(
            verified,
            BootScope::new([3; 16]),
            AuthorityEpoch(4),
            LeaseId::new([5; 32]),
        )
        .unwrap();
        let request = crate::vortix_core::privileged::PrivilegedRequest::new(
            &root.principal(),
            HelperEpoch::new(6).unwrap(),
            RequestSequence::new(1).unwrap(),
            PrivilegedOperation::StartTunnel(plan),
        )
        .unwrap();
        HelperRequest {
            id: 2,
            op: HelperOp::Execute(Box::new(request)),
        }
    }

    #[test]
    fn descriptor_free_handshake_round_trips() {
        let (mut sender, inbound) = UnixStream::pair().unwrap();
        let request = handshake();
        send_request(&mut sender, &request, &[]).unwrap();
        let envelope = receive_request(&inbound).unwrap();
        assert_eq!(envelope.request.id, request.id);
        assert!(envelope.descriptors.is_empty());
    }

    #[test]
    fn declared_material_descriptor_round_trips_with_cloexec() {
        let mut descriptor = tempfile::tempfile().unwrap();
        descriptor.write_all(b"private-key").unwrap();
        descriptor.flush().unwrap();
        descriptor.seek(SeekFrom::Start(0)).unwrap();
        let (mut sender, inbound) = UnixStream::pair().unwrap();
        let request = wireguard_request();
        send_request(&mut sender, &request, &[descriptor.as_raw_fd()]).unwrap();
        let mut envelope = receive_request(&inbound).unwrap();
        assert_eq!(envelope.descriptors.len(), 1);
        let flags = unsafe { libc::fcntl(envelope.descriptors[0].as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let mut body = String::new();
        envelope.descriptors[0].read_to_string(&mut body).unwrap();
        assert_eq!(body, "private-key");
    }

    #[test]
    fn descriptor_count_must_match_operation_material_identity() {
        let descriptor = tempfile::tempfile().unwrap();
        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        assert!(matches!(
            send_request(&mut sender, &handshake(), &[descriptor.as_raw_fd()]),
            Err(DescriptorTransportError::DescriptorCountMismatch)
        ));
        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        assert!(matches!(
            send_request(&mut sender, &wireguard_request(), &[]),
            Err(DescriptorTransportError::DescriptorCountMismatch)
        ));

        let (mut sender, inbound) = UnixStream::pair().unwrap();
        let frame = encode_request_frame(&handshake()).unwrap();
        send_frame(&mut sender, &frame, &[descriptor.as_raw_fd()]).unwrap();
        assert!(matches!(
            receive_request(&inbound),
            Err(DescriptorTransportError::DescriptorCountMismatch)
        ));
    }

    #[test]
    fn interactive_openvpn_requires_profile_material_plus_one_credential_descriptor() {
        let request = interactive_openvpn_request();
        assert_eq!(expected_descriptor_count(&request), 2);
        let descriptor = tempfile::tempfile().unwrap();
        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        assert!(matches!(
            send_request(&mut sender, &request, &[descriptor.as_raw_fd()]),
            Err(DescriptorTransportError::DescriptorCountMismatch)
        ));
    }

    #[test]
    fn descriptor_batches_over_kernel_single_message_limit_remain_ordered() {
        let descriptor = tempfile::tempfile().unwrap();
        let raw = vec![descriptor.as_raw_fd(); MAX_FDS_PER_MESSAGE + 3];
        let frame = encode_request_frame(&handshake()).unwrap();
        let (mut sender, inbound) = UnixStream::pair().unwrap();

        send_frame(&mut sender, &frame, &raw).unwrap();
        let (received_frame, descriptors) = receive_frame(&inbound).unwrap();

        assert_eq!(received_frame, frame);
        assert_eq!(descriptors.len(), raw.len());
    }
}
