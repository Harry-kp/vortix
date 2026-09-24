//! Small identity types shared by the process, protocol and ownership layers.

use serde::{Deserialize, Serialize};

/// Opaque operation identity scoped by the monotonic authority epoch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationId(String);

impl OperationId {
    #[must_use]
    pub fn parse(value: impl Into<String>) -> Option<Self> {
        let value = Self(value.into());
        value.sequence().map(|_| value)
    }

    pub(crate) fn from_parts(authority_epoch: AuthorityEpoch, sequence: u64) -> Self {
        Self(format!("op-{:016x}-{sequence:016x}", authority_epoch.0))
    }

    pub(crate) fn sequence(&self) -> Option<u64> {
        parse_scoped_id(&self.0, "op").map(|(_, sequence)| sequence)
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Self(String::deserialize(deserializer)?);
        value
            .sequence()
            .map(|_| value)
            .ok_or_else(|| serde::de::Error::custom("invalid service-issued operation ID"))
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn parse_scoped_id(value: &str, prefix: &str) -> Option<(u64, u64)> {
    let rest = value.strip_prefix(prefix)?.strip_prefix('-')?;
    let (epoch, sequence) = rest.split_once('-')?;
    if epoch.len() != 16
        || sequence.len() != 16
        || !epoch.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !sequence.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((
        u64::from_str_radix(epoch, 16).ok()?,
        u64::from_str_radix(sequence, 16).ok()?,
    ))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityEpoch(pub u64);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyDigest(pub String);

/// Identity of one tunnel generation, recorded with its ownership receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TunnelRevision {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
}
