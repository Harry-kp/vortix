//! Black-box U12 activation boundary. Typed execution exists only behind the
//! future U13 enrollment capability; neither wire input nor the staged binary
//! can activate it.

use serde_json::json;
use vortix::helper::{
    decode_request_frame, decode_response_frame, encode_request_frame, negotiate_staged,
    parse_request, HelperCapability, HelperClientHello, HelperError, HelperOp, HelperRequest,
    HelperResponse, HelperResult, MAX_HELPER_FRAME_BYTES,
};
use vortix::vortix_core::privileged::{OperationDigest, ServiceInstanceClaim};

#[test]
fn arbitrary_execution_shapes_never_decode_as_helper_requests() {
    for payload in [
        json!({"id": 1, "op": {"kind": "execute", "payload": {"command": "/bin/sh"}}}),
        json!({"id": 1, "op": {"kind": "execute", "payload": {"environment": {"PATH": "/tmp"}}}}),
        json!({"id": 1, "op": {"kind": "execute", "payload": {"profile": "PostUp = id"}}}),
    ] {
        assert!(parse_request(&serde_json::to_vec(&payload).unwrap()).is_err());
    }

    assert!(matches!(
        parse_request(&vec![0; MAX_HELPER_FRAME_BYTES + 1]),
        Err(HelperError::FrameTooLarge { .. })
    ));
}

#[test]
fn installed_helper_still_has_no_server_activation_path() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_vortix-helper")) // xtask:allow-subprocess: black-box activation boundary
        .arg("--serve")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(78));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not enrolled"));
}

#[test]
fn helper_framing_is_fragment_safe_symmetric_and_stricter_than_daemon_ipc() {
    let service =
        ServiceInstanceClaim::systemd(42, 99, OperationDigest::of_bytes(b"daemon"), [7; 32])
            .unwrap();
    let request = HelperRequest {
        id: 7,
        op: HelperOp::Handshake(HelperClientHello::current(
            501,
            service,
            vec![HelperCapability::Handshake],
        )),
    };
    let encoded = encode_request_frame(&request).unwrap();
    for split in 0..encoded.len() {
        assert!(decode_request_frame(&encoded[..split]).unwrap().is_none());
    }
    let (decoded, consumed) = decode_request_frame(&encoded).unwrap().unwrap();
    assert_eq!(decoded.id, 7);
    assert_eq!(consumed, encoded.len());

    let hello = match request.op {
        HelperOp::Handshake(hello) => negotiate_staged(&hello).unwrap(),
        HelperOp::Execute(_) => unreachable!(),
    };
    let response = HelperResponse {
        id: 7,
        result: Ok(HelperResult::Handshake(hello)),
    };
    let encoded = vortix::helper::encode_response_frame(&response).unwrap();
    let (decoded, consumed) = decode_response_frame(&encoded).unwrap().unwrap();
    assert_eq!(decoded.id, 7);
    assert_eq!(consumed, encoded.len());

    let oversized = u32::try_from(MAX_HELPER_FRAME_BYTES + 1)
        .unwrap()
        .to_be_bytes();
    assert!(decode_request_frame(&oversized).is_err());
    assert!(decode_response_frame(&oversized).is_err());
}
