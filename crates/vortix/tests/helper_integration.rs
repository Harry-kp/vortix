//! Black-box U12 activation boundary. Typed execution exists only behind the
//! future U13 enrollment capability; neither wire input nor the staged binary
//! can activate it.

use serde_json::json;
use vortix::helper::{parse_request, HelperError, MAX_HELPER_FRAME_BYTES};

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
