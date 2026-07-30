//! Strict, bounded root-owned helper ledger envelope.

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    has_duplicates, BoundedVec, ObservedChildIdentity, ReplayRecord, ResourceKind, ResourceTag,
    MAX_RESOURCE_ITEMS,
};

const HELPER_LEDGER_SCHEMA_VERSION: u16 = 2;

/// Durable lifecycle phase for one exact helper-managed resource. Intent is
/// written before an external effect; release intent is written before
/// teardown. A restart may observe pending resources, but observation alone
/// never manufactures a live-session child ownership capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HelperResourceState {
    PendingEffect,
    Owned,
    PendingRelease,
}

/// One exact resource plus its crash-recovery phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperLedgerResource {
    resource: ResourceTag,
    state: HelperResourceState,
}

impl HelperLedgerResource {
    pub(crate) const fn pending(resource: ResourceTag) -> Self {
        Self {
            resource,
            state: HelperResourceState::PendingEffect,
        }
    }

    pub(crate) const fn owned(resource: ResourceTag) -> Self {
        Self {
            resource,
            state: HelperResourceState::Owned,
        }
    }

    pub(crate) const fn releasing(resource: ResourceTag) -> Self {
        Self {
            resource,
            state: HelperResourceState::PendingRelease,
        }
    }

    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    pub(crate) const fn state(&self) -> HelperResourceState {
        self.state
    }
}

/// Durable helper facts. Persisted child identities remain observation and
/// containment evidence after restart; deserialization never mints `OwnedChild`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HelperLedgerRecord {
    schema_version: u16,
    replay: ReplayRecord,
    resources: Vec<HelperLedgerResource>,
    child_observations: Vec<ObservedChildIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerWire {
    schema_version: u16,
    replay: ReplayRecord,
    resources: BoundedVec<HelperLedgerResource, MAX_RESOURCE_ITEMS>,
    child_observations: BoundedVec<ObservedChildIdentity, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperLedgerRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HelperLedgerWire::deserialize(deserializer)?;
        Self::new_with_schema(
            wire.schema_version,
            wire.replay,
            wire.resources.into_vec(),
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
            resources: Vec::new(),
            child_observations: Vec::new(),
        }
    }

    pub(crate) fn new(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_schema(
            HELPER_LEDGER_SCHEMA_VERSION,
            replay,
            resources,
            child_observations,
        )
    }

    fn new_with_schema(
        schema_version: u16,
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        if schema_version != HELPER_LEDGER_SCHEMA_VERSION
            || resources.len() > MAX_RESOURCE_ITEMS
            || child_observations.len() > MAX_RESOURCE_ITEMS
            || has_duplicates(resources.iter().map(HelperLedgerResource::resource))
            || resources.iter().any(|entry| {
                entry
                    .resource()
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
                !resource_is_accounted(&resources, tunnel)
                    || !resource_is_accounted(&resources, &group)
            })
        {
            return Err("invalid helper ownership ledger");
        }
        Ok(Self {
            schema_version,
            replay,
            resources,
            child_observations,
        })
    }

    #[cfg(test)]
    pub(crate) fn resources(&self) -> &[HelperLedgerResource] {
        &self.resources
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ReplayRecord,
        Vec<HelperLedgerResource>,
        Vec<ObservedChildIdentity>,
    ) {
        (self.replay, self.resources, self.child_observations)
    }
}

fn resource_is_accounted(resources: &[HelperLedgerResource], resource: &ResourceTag) -> bool {
    resources.iter().any(|entry| {
        entry.resource() == resource
            && matches!(
                entry.state(),
                HelperResourceState::Owned | HelperResourceState::PendingRelease
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> ResourceTag {
        ResourceTag::tunnel(
            crate::vortix_core::profile::ProfileId::parse(
                "a".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN),
            )
            .unwrap(),
            7,
        )
        .unwrap()
    }

    #[test]
    fn resource_transitions_roundtrip_without_minting_child_ownership() {
        let replay: ReplayRecord = serde_json::from_value(serde_json::json!({
            "state": "unused",
            "record": {
                "schema_version": 1,
                "authority_epoch": 3,
                "lease_id": vec![5; 32],
                "principal_binding": vec![7; 32],
                "initial_helper_epoch": 8
            }
        }))
        .unwrap();
        let resource = tunnel();
        let record = HelperLedgerRecord::new(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            Vec::new(),
        )
        .unwrap();

        let encoded = serde_json::to_vec(&record).unwrap();
        let decoded: HelperLedgerRecord = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.resources().len(), 1);
        assert_eq!(decoded.resources()[0].resource(), &resource);
        assert_eq!(
            decoded.resources()[0].state(),
            HelperResourceState::PendingEffect
        );
    }

    #[test]
    fn duplicate_resources_and_child_evidence_without_owned_topology_are_rejected() {
        let replay: ReplayRecord = serde_json::from_value(serde_json::json!({
            "state": "unused",
            "record": {
                "schema_version": 1,
                "authority_epoch": 3,
                "lease_id": vec![5; 32],
                "principal_binding": vec![7; 32],
                "initial_helper_epoch": 8
            }
        }))
        .unwrap();
        let resource = tunnel();
        assert!(HelperLedgerRecord::new(
            replay,
            vec![
                HelperLedgerResource::pending(resource.clone()),
                HelperLedgerResource::owned(resource),
            ],
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn oversized_and_unknown_ledger_shapes_fail_before_allocation_or_use() {
        let oversized = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "resources": vec![serde_json::Value::Null; MAX_RESOURCE_ITEMS + 1],
            "child_observations": []
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(oversized).is_err());

        let unknown = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "resources": [],
            "child_observations": [],
            "path": "/tmp/escape"
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown).is_err());
    }
}
