//! Length-prefixed JSON frame codec for IPC (plan 015 phase D U16 / plan 010).
//!
//! Wire format:
//! ```text
//! ┌─────────────────┬─────────────────────┐
//! │ 4-byte BE len   │ JSON body (UTF-8)   │
//! └─────────────────┴─────────────────────┘
//! ```
//!
//! Length = JSON body byte length (not including the 4-byte prefix).
//! Max body size is bounded by [`MAX_FRAME_BYTES`] to defend against
//! a runaway / corrupt-prefix denial-of-service.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Soft cap on a single frame body. 1 MiB is generous for IPC's
/// envelope shape (typical payloads are < 1 KB).
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Frame encoding error.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame body too large: {got} bytes, max {max}")]
    TooLarge { got: usize, max: usize },
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("IO failure during frame transfer: {0}")]
    Io(#[from] std::io::Error),
}

/// Encode a JSON-serializable value as a length-prefixed frame.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] when the body would exceed
/// [`MAX_FRAME_BYTES`] or [`FrameError::Serialize`] when serde fails.
///
/// # Panics
///
/// Panics if the body length cannot be converted to `u32` — only
/// reachable if [`MAX_FRAME_BYTES`] is bumped above `u32::MAX`, which
/// no realistic IPC payload would hit.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            got: body.len(),
            max: MAX_FRAME_BYTES,
        });
    }
    let mut out = Vec::with_capacity(4 + body.len());
    let len = u32::try_from(body.len()).expect("MAX_FRAME_BYTES fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a single length-prefixed frame from `buf`. Returns
/// `Ok(None)` when the buffer doesn't yet contain a complete frame
/// (the caller should read more bytes).
///
/// On success returns `(value, bytes_consumed)` so the caller can
/// advance their buffer.
///
/// # Errors
///
/// Returns [`FrameError::TooLarge`] when a prefix declares a body
/// over [`MAX_FRAME_BYTES`] or [`FrameError::Serialize`] when the
/// body isn't valid JSON for type `T`.
///
/// # Panics
///
/// Cannot panic — the `buf[0..4].try_into()` cast checks length
/// before; the assertion message inside is dead code in practice.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<Option<(T, usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len_bytes: [u8; 4] = buf[0..4].try_into().expect("4 bytes");
    let body_len = u32::from_be_bytes(len_bytes) as usize;
    if body_len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge {
            got: body_len,
            max: MAX_FRAME_BYTES,
        });
    }
    if buf.len() < 4 + body_len {
        return Ok(None);
    }
    let body = &buf[4..4 + body_len];
    let value: T = serde_json::from_slice(body)?;
    Ok(Some((value, 4 + body_len)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Msg {
        kind: String,
        value: i32,
    }

    #[test]
    fn encode_decode_round_trip() {
        let m = Msg {
            kind: "hello".into(),
            value: 42,
        };
        let bytes = encode_frame(&m).unwrap();
        let (decoded, consumed): (Msg, usize) = decode_frame(&bytes).unwrap().unwrap();
        assert_eq!(decoded, m);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn decode_with_insufficient_prefix_returns_none() {
        let buf = [0x00u8; 3];
        let res: Result<Option<(Msg, usize)>, _> = decode_frame(&buf);
        assert!(matches!(res, Ok(None)));
    }

    #[test]
    fn decode_with_partial_body_returns_none() {
        let m = Msg {
            kind: "x".into(),
            value: 1,
        };
        let mut bytes = encode_frame(&m).unwrap();
        bytes.truncate(bytes.len() - 1); // drop last body byte
        let res: Result<Option<(Msg, usize)>, _> = decode_frame(&bytes);
        assert!(matches!(res, Ok(None)));
    }

    #[test]
    fn decode_with_extra_bytes_consumes_only_one_frame() {
        let m = Msg {
            kind: "a".into(),
            value: 1,
        };
        let mut bytes = encode_frame(&m).unwrap();
        bytes.extend_from_slice(b"trailing-garbage-not-part-of-frame");
        let original_frame_len = bytes.len() - "trailing-garbage-not-part-of-frame".len();
        let (decoded, consumed): (Msg, usize) = decode_frame(&bytes).unwrap().unwrap();
        assert_eq!(decoded, m);
        assert_eq!(consumed, original_frame_len);
    }

    #[test]
    fn oversized_length_prefix_returns_too_large_error() {
        let mut buf = vec![0xFFu8; 4]; // claim 4 GiB body
        buf.extend_from_slice(b"{}");
        let res: Result<Option<(Msg, usize)>, _> = decode_frame(&buf);
        assert!(matches!(res, Err(FrameError::TooLarge { .. })));
    }

    #[test]
    fn invalid_utf8_body_returns_serialize_error() {
        // Construct a frame that says 4-byte body 0xC0 0xC0 0xC0 0xC0
        // (invalid UTF-8, never a valid JSON document).
        let mut buf = 4u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0xC0, 0xC0, 0xC0, 0xC0]);
        let res: Result<Option<(Msg, usize)>, _> = decode_frame(&buf);
        assert!(matches!(res, Err(FrameError::Serialize(_))));
    }
}
