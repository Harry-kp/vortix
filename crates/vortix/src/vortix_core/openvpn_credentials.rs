//! Memory-only framing for one `OpenVPN` management authentication attempt.
//!
//! The frame is carried only through secret memory and an inherited local
//! descriptor. It has no serde implementation and is never durable state.

use std::fmt::{Debug, Formatter};

use zeroize::Zeroizing;

const MAGIC: &[u8] = b"VORTIX-OVPN-CREDENTIALS\0";
const MAX_USERNAME_BYTES: usize = 1024;
const MAX_PASSWORD_BYTES: usize = 8 * 1024;
const MAX_ANSWER_BYTES: usize = 4 * 1024;
pub(crate) const MAX_CREDENTIAL_FRAME_BYTES: usize = 16 * 1024;

pub(crate) struct DecodedOpenVpnCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    answer: Zeroizing<Vec<u8>>,
}

impl Debug for DecodedOpenVpnCredentials {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DecodedOpenVpnCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("answer", &"[REDACTED]")
            .finish()
    }
}

impl DecodedOpenVpnCredentials {
    pub(crate) fn answer_is_empty(&self) -> bool {
        self.answer.is_empty()
    }

    pub(crate) fn into_parts(self) -> (Zeroizing<String>, Zeroizing<String>, Zeroizing<Vec<u8>>) {
        (self.username, self.password, self.answer)
    }
}

pub(crate) fn encode(username: &str, password: &str, answer: Option<&str>) -> Vec<u8> {
    let answer = answer.unwrap_or_default();
    let mut bytes =
        Vec::with_capacity(MAGIC.len() + username.len() + password.len() + answer.len() + 12);
    bytes.extend_from_slice(MAGIC);
    for value in [username, password, answer] {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes
}

pub(crate) fn decode(bytes: &[u8]) -> Option<DecodedOpenVpnCredentials> {
    if bytes.len() > MAX_CREDENTIAL_FRAME_BYTES {
        return None;
    }
    let mut remaining = bytes.strip_prefix(MAGIC)?;
    let mut next = |limit: usize| {
        let (raw_len, rest) = remaining.split_at_checked(4)?;
        let len = usize::try_from(u32::from_be_bytes(raw_len.try_into().ok()?)).ok()?;
        if len > limit {
            return None;
        }
        let (value, rest) = rest.split_at_checked(len)?;
        remaining = rest;
        if value.iter().any(u8::is_ascii_control) {
            return None;
        }
        String::from_utf8(value.to_vec()).ok()
    };
    let username = Zeroizing::new(next(MAX_USERNAME_BYTES)?);
    let password = Zeroizing::new(next(MAX_PASSWORD_BYTES)?);
    let answer = Zeroizing::new(next(MAX_ANSWER_BYTES)?.into_bytes());
    if username.is_empty() || password.is_empty() || !remaining.is_empty() {
        return None;
    }
    Some(DecodedOpenVpnCredentials {
        username,
        password,
        answer,
    })
}
