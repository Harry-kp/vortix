//! Commands admitted by the canonical control service.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::vortix_core::control::model::{ChallengeId, ClientId};
use crate::vortix_core::profile::ProfileId;
use crate::vortix_core::state::killswitch::KillSwitchMode;

/// User mutation vocabulary shared by local and future remote control modes.
///
/// Interactive answers deliberately do not live in this serializable enum;
/// they travel as [`ChallengeResponse`], whose secret payload has no
/// `Clone`, `Debug`, or serde implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum UserCommand {
    Connect {
        profile_id: ProfileId,
        /// Exact canonical conflict the user acknowledged after preflight.
        /// Missing remains the safe default for old serialized clients.
        #[serde(default)]
        conflict_acknowledgement: Option<crate::vortix_core::engine::registry::Conflict>,
    },
    /// Make one tunnel the sole requested connection in a single durable
    /// desired-state transition. The service tears down every other managed
    /// tunnel before it dispatches the target connect.
    ConnectExclusive {
        profile_id: ProfileId,
    },
    Disconnect {
        profile_id: Option<ProfileId>,
    },
    Reconnect {
        profile_id: Option<ProfileId>,
    },
    ForceDisconnect {
        profile_id: Option<ProfileId>,
    },
    SetKillSwitch {
        #[serde(with = "crate::vortix_core::state::killswitch::serde_mode_slug")]
        mode: KillSwitchMode,
    },
    /// Commit a profile body previously prepared in a memory-only mutation
    /// executor. The durable command carries only the new stable identity;
    /// private protocol configuration never enters operation state/events.
    ImportProfile {
        profile_id: ProfileId,
    },
    RenameProfile {
        profile_id: ProfileId,
        new_display_name: String,
    },
    DeleteProfile {
        profile_id: ProfileId,
    },
}

/// Service-clock deadline in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Deadline(pub u64);

/// Caller-chosen retry key. Its meaning is scoped to one control authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.len() <= 128
    }
}

/// A mutation plus the admission metadata required by the operation model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    pub command: UserCommand,
    pub idempotency_key: IdempotencyKey,
    pub deadline: Deadline,
}

/// Memory-only secret. Dropping it overwrites its allocation before release.
///
/// It intentionally implements neither `Clone`, `Debug`, nor serde traits.
///
/// ```compile_fail
/// use vortix::vortix_core::control::Secret;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<Secret>();
/// ```
///
/// ```compile_fail
/// use vortix::vortix_core::control::Secret;
/// let secret = Secret::new(b"answer".to_vec());
/// let _ = serde_json::to_string(&secret);
/// ```
pub struct Secret(Box<[u8]>);

impl Secret {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into().into_boxed_slice())
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.len() <= 16 * 1024
    }

    /// Borrow credential bytes only at the final in-process protocol boundary.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Transfer through an existing byte-oriented local client boundary.
    /// The source allocation is cleared before this value is returned; the
    /// receiver must immediately re-wrap the returned bytes in `Secret`.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        let bytes = self.0.to_vec();
        self.clear();
        bytes
    }

    /// Build a memory-only `OpenVPN` credential response. The framing is an
    /// internal service/worker contract and is never serialized, journaled,
    /// logged, or persisted.
    #[must_use]
    pub fn openvpn_credentials(
        username: &str,
        password: &str,
        challenge_answer: Option<&str>,
    ) -> Self {
        const MAGIC: &[u8] = b"VORTIX-OVPN-CREDENTIALS\0";
        let answer = challenge_answer.unwrap_or_default();
        let mut bytes =
            Vec::with_capacity(MAGIC.len() + username.len() + password.len() + answer.len() + 12);
        bytes.extend_from_slice(MAGIC);
        for value in [username, password, answer] {
            let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        Self::new(bytes)
    }

    pub(crate) fn decode_openvpn_credentials(
        &self,
    ) -> Option<(
        zeroize::Zeroizing<String>,
        zeroize::Zeroizing<String>,
        Secret,
    )> {
        const MAGIC: &[u8] = b"VORTIX-OVPN-CREDENTIALS\0";
        let mut bytes = self.expose().strip_prefix(MAGIC)?;
        let mut next = || {
            let (raw_len, rest) = bytes.split_at_checked(4)?;
            let len = usize::try_from(u32::from_be_bytes(raw_len.try_into().ok()?)).ok()?;
            let (value, rest) = rest.split_at_checked(len)?;
            bytes = rest;
            String::from_utf8(value.to_vec()).ok()
        };
        let username = zeroize::Zeroizing::new(next()?);
        let password = zeroize::Zeroizing::new(next()?);
        let answer = Secret::new(next()?.into_bytes());
        bytes.is_empty().then_some((username, password, answer))
    }

    fn clear(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.clear();
    }
}

/// One attempt to answer a service-owned interactive challenge.
pub struct ChallengeResponse {
    pub challenge_id: ChallengeId,
    pub client_id: ClientId,
    pub answer: Secret,
}

impl fmt::Debug for ChallengeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeResponse")
            .field("challenge_id", &self.challenge_id)
            .field("client_id", &self.client_id)
            .field("answer", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Secret, UserCommand};

    #[test]
    fn secret_clear_overwrites_every_initialized_byte() {
        let mut secret = Secret::new(b"compiler-resistant-answer".to_vec());
        secret.clear();
        assert!(secret.0.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn openvpn_credentials_round_trip_only_through_memory_secret() {
        let secret = Secret::openvpn_credentials("alice", "correct horse", Some("123456"));
        let (username, password, answer) = secret.decode_openvpn_credentials().unwrap();
        assert_eq!(username.as_str(), "alice");
        assert_eq!(password.as_str(), "correct horse");
        assert_eq!(answer.expose(), b"123456");
    }

    #[test]
    fn ordinary_challenge_answer_is_not_misread_as_credentials() {
        assert!(Secret::new(b"123456".to_vec())
            .decode_openvpn_credentials()
            .is_none());
    }

    #[test]
    fn legacy_connect_json_defaults_to_unconfirmed_topology() {
        let encoded = format!(
            r#"{{"Connect":{{"profile_id":"{}"}}}}"#,
            "a".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN)
        );
        let command: UserCommand = serde_json::from_str(&encoded).unwrap();
        assert!(matches!(
            command,
            UserCommand::Connect {
                conflict_acknowledgement: None,
                ..
            }
        ));
    }
}
