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
    use super::Secret;

    #[test]
    fn secret_clear_overwrites_every_initialized_byte() {
        let mut secret = Secret::new(b"compiler-resistant-answer".to_vec());
        secret.clear();
        assert!(secret.0.iter().all(|byte| *byte == 0));
    }
}
