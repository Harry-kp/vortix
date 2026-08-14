//! Strict, bounded root-owned helper ledger envelope.

use serde::{Deserialize, Deserializer, Serialize};

use super::{
    has_duplicates, BoundedVec, ObservedChildIdentity, PolicyProjection, ReplayRecord,
    ResourceKind, ResourceTag, MAX_RESOURCE_ITEMS,
};

const HELPER_LEDGER_SCHEMA_VERSION: u16 = 4;

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

/// Durable intended and last-observed payload for one exact policy resource.
/// `effective` is absent until read-back proves the first application. During
/// replacement, the old effective projection remains available beside the new
/// intent so restart recovery can distinguish both sides of an ambiguous
/// effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperLedgerPolicy {
    resource: ResourceTag,
    intended: PolicyProjection,
    effective: Option<PolicyProjection>,
}

impl HelperLedgerPolicy {
    pub(crate) fn new(
        resource: ResourceTag,
        intended: PolicyProjection,
        effective: Option<PolicyProjection>,
    ) -> Result<Self, &'static str> {
        if resource != *intended.policy()
            || effective
                .as_ref()
                .is_some_and(|projection| projection.policy() != &resource)
        {
            return Err("policy projection does not match its resource");
        }
        Ok(Self {
            resource,
            intended,
            effective,
        })
    }

    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    pub(crate) const fn intended(&self) -> &PolicyProjection {
        &self.intended
    }

    pub(crate) const fn effective(&self) -> Option<&PolicyProjection> {
        self.effective.as_ref()
    }

    pub(crate) fn into_parts(self) -> (ResourceTag, PolicyProjection, Option<PolicyProjection>) {
        (self.resource, self.intended, self.effective)
    }
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
    policy_projections: Vec<HelperLedgerPolicy>,
    child_observations: Vec<ObservedChildIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerWire {
    schema_version: u16,
    replay: ReplayRecord,
    resources: BoundedVec<HelperLedgerResource, MAX_RESOURCE_ITEMS>,
    policy_projections: BoundedVec<HelperLedgerPolicy, MAX_RESOURCE_ITEMS>,
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
            wire.policy_projections.into_vec(),
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
            policy_projections: Vec::new(),
            child_observations: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_policies(replay, resources, Vec::new(), child_observations)
    }

    pub(crate) fn new_with_policies(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_schema(
            HELPER_LEDGER_SCHEMA_VERSION,
            replay,
            resources,
            policy_projections,
            child_observations,
        )
    }

    fn new_with_schema(
        schema_version: u16,
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        if schema_version != HELPER_LEDGER_SCHEMA_VERSION
            || resources.len() > MAX_RESOURCE_ITEMS
            || policy_projections.len() > MAX_RESOURCE_ITEMS
            || child_observations.len() > MAX_RESOURCE_ITEMS
            || has_duplicates(resources.iter().map(HelperLedgerResource::resource))
            || resources.iter().any(|entry| {
                entry
                    .resource()
                    .authority_epoch()
                    .is_some_and(|epoch| epoch != replay.authority_epoch())
            })
            || has_duplicates(policy_projections.iter().map(HelperLedgerPolicy::resource))
            || policy_projections.iter().any(|entry| {
                let Some(resource) = resources
                    .iter()
                    .find(|resource| resource.resource() == entry.resource())
                else {
                    return true;
                };
                !matches!(
                    entry.resource().kind(),
                    ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
                ) || entry.resource() != entry.intended().policy()
                    || !entry.intended().is_valid()
                    || entry.effective().is_some_and(|projection| {
                        projection.policy() != entry.resource() || !projection.is_valid()
                    })
                    || (resource.state() != HelperResourceState::PendingEffect
                        && entry.effective() != Some(entry.intended()))
            })
            || resources.iter().any(|entry| {
                matches!(
                    entry.resource().kind(),
                    ResourceKind::Firewall | ResourceKind::Dns | ResourceKind::Routes
                ) && !policy_projections
                    .iter()
                    .any(|policy| policy.resource() == entry.resource())
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
            policy_projections,
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
        Vec<HelperLedgerPolicy>,
        Vec<ObservedChildIdentity>,
    ) {
        (
            self.replay,
            self.resources,
            self.policy_projections,
            self.child_observations,
        )
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
                "schema_version": crate::vortix_core::privileged::CONTRACT_SCHEMA_VERSION,
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
                "schema_version": crate::vortix_core::privileged::CONTRACT_SCHEMA_VERSION,
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
            "policy_projections": [],
            "child_observations": []
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(oversized).is_err());

        let oversized_policies = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "resources": [],
            "policy_projections": vec![serde_json::Value::Null; MAX_RESOURCE_ITEMS + 1],
            "child_observations": []
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(oversized_policies).is_err());

        let unknown = serde_json::json!({
            "schema_version": HELPER_LEDGER_SCHEMA_VERSION,
            "replay": {"state":"unused","record":{}},
            "resources": [],
            "policy_projections": [],
            "child_observations": [],
            "path": "/tmp/escape"
        });
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown).is_err());
    }

    #[test]
    fn policy_projection_must_match_exact_root_owned_resource_and_state() {
        let replay: ReplayRecord = serde_json::from_value(serde_json::json!({
            "state": "unused",
            "record": {
                "schema_version": crate::vortix_core::privileged::CONTRACT_SCHEMA_VERSION,
                "authority_epoch": 3,
                "lease_id": vec![5; 32],
                "principal_binding": vec![7; 32],
                "initial_helper_epoch": 8
            }
        }))
        .unwrap();
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            1,
            ResourceKind::Firewall,
        )
        .unwrap();
        let projection = PolicyProjection::Blocking {
            policy: resource.clone(),
            tunnels: Vec::new(),
        };
        assert!(HelperLedgerRecord::new_with_policies(
            replay.clone(),
            vec![HelperLedgerResource::owned(resource.clone())],
            vec![HelperLedgerPolicy::new(resource.clone(), projection.clone(), None).unwrap()],
            Vec::new(),
        )
        .is_err());

        let record = HelperLedgerRecord::new_with_policies(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            Vec::new(),
        )
        .unwrap();
        let mut wire = serde_json::to_value(record).unwrap();
        wire["policy_projections"][0]["intended"]["policy"]["generation"] = serde_json::json!(2);
        assert!(serde_json::from_value::<HelperLedgerRecord>(wire).is_err());
    }

    #[test]
    fn policy_projection_rejects_duplicate_tunnel_facts_from_the_root_ledger() {
        let replay: ReplayRecord = serde_json::from_value(serde_json::json!({
            "state": "unused",
            "record": {
                "schema_version": crate::vortix_core::privileged::CONTRACT_SCHEMA_VERSION,
                "authority_epoch": 3,
                "lease_id": vec![5; 32],
                "principal_binding": vec![7; 32],
                "initial_helper_epoch": 8
            }
        }))
        .unwrap();
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            1,
            ResourceKind::Firewall,
        )
        .unwrap();
        let subject = crate::vortix_core::privileged::PrivilegedFirewallTunnel::new(
            tunnel(),
            vec!["198.51.100.1".parse().unwrap()],
            Vec::new(),
            crate::vortix_core::privileged::PrivilegedFirewallRole::PendingEndpoint,
        )
        .unwrap();
        let projection = PolicyProjection::Blocking {
            policy: resource.clone(),
            tunnels: vec![subject],
        };
        let record = HelperLedgerRecord::new_with_policies(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            Vec::new(),
        )
        .unwrap();
        let mut wire = serde_json::to_value(record).unwrap();
        let duplicate = wire["policy_projections"][0]["intended"]["tunnels"][0].clone();
        wire["policy_projections"][0]["intended"]["tunnels"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);

        assert!(serde_json::from_value::<HelperLedgerRecord>(wire).is_err());
    }
}
