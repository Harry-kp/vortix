//! Strict, bounded root-owned helper ledger envelope.

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    has_duplicates, BoundedVec, ObservedChildIdentity, ReplayRecord, ResourceKind, ResourceTag,
    MAX_RESOURCE_ITEMS,
};

const HELPER_LEDGER_SCHEMA_VERSION: u16 = 1;

/// Durable helper facts. Persisted child identities remain observation and
/// containment evidence after restart; deserialization never mints `OwnedChild`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HelperLedgerRecord {
    schema_version: u16,
    replay: ReplayRecord,
    owned_resources: Vec<ResourceTag>,
    child_observations: Vec<ObservedChildIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerWire {
    schema_version: u16,
    replay: ReplayRecord,
    owned_resources: BoundedVec<ResourceTag, MAX_RESOURCE_ITEMS>,
    child_observations: BoundedVec<ObservedChildIdentity, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperLedgerRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HelperLedgerWire::deserialize(deserializer)?;
        Self::new(
            wire.schema_version,
            wire.replay,
            wire.owned_resources.into_vec(),
            wire.child_observations.into_vec(),
        )
        .map_err(serde::de::Error::custom)
    }
}

impl HelperLedgerRecord {
    pub(crate) fn empty(replay: ReplayRecord) -> Self {
        Self {
            schema_version: HELPER_LEDGER_SCHEMA_VERSION,
            replay,
            owned_resources: Vec::new(),
            child_observations: Vec::new(),
        }
    }

    fn new(
        schema_version: u16,
        replay: ReplayRecord,
        owned_resources: Vec<ResourceTag>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        if schema_version != HELPER_LEDGER_SCHEMA_VERSION
            || has_duplicates(&owned_resources)
            || owned_resources.iter().any(|resource| {
                resource
                    .authority_epoch()
                    .is_some_and(|epoch| epoch != replay.authority_epoch())
            })
            || has_duplicates(
                child_observations
                    .iter()
                    .map(ObservedChildIdentity::resource),
            )
            || child_observations.iter().any(|child| {
                let tunnel = child.resource();
                let Some(profile) = tunnel.profile_id() else {
                    return true;
                };
                let Ok(group) = ResourceTag::profile(
                    profile.clone(),
                    tunnel.generation(),
                    ResourceKind::ProcessGroup,
                ) else {
                    return true;
                };
                !owned_resources.contains(tunnel) || !owned_resources.contains(&group)
            })
        {
            return Err("invalid helper ownership ledger");
        }
        Ok(Self {
            schema_version,
            replay,
            owned_resources,
            child_observations,
        })
    }

    pub(crate) fn replace_replay(&mut self, replay: ReplayRecord) {
        self.replay = replay;
    }

    pub(crate) fn into_replay(self) -> ReplayRecord {
        self.replay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_and_unknown_ledger_shapes_fail_before_allocation_or_use() {
        let oversized = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "owned_resources": vec![serde_json::Value::Null; MAX_RESOURCE_ITEMS + 1],
            "child_observations": []
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(oversized).is_err());

        let unknown = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "owned_resources": [],
            "child_observations": [],
            "path": "/tmp/escape"
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown).is_err());
    }
}
