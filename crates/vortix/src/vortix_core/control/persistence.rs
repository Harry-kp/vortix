//! Storage-neutral durable control intent boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::SystemTime;

use thiserror::Error;

use serde::{Deserialize, Serialize};

use crate::vortix_core::control::model::{
    AuthorityEpoch, DesiredState, OperationId, OperationRecord, OperationResult, OperationStatus,
    PolicyDigest, RequestedTunnelState,
};
use crate::vortix_core::profile::ProfileId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootEligibility {
    Eligible,
    InteractiveCredentials,
    UnsupportedKeyProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootConnection {
    pub enabled: bool,
    pub eligibility: BootEligibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedResources {
    pub routes: BTreeSet<String>,
    pub dns_digest: PolicyDigest,
    pub firewall_digest: PolicyDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedTombstone {
    pub authority_epoch: AuthorityEpoch,
    pub generation: u64,
    /// Exact owned tunnel generation. Older Standard-mode state omitted this
    /// field and falls back to `generation`; Background activation requires
    /// newly persisted exact ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_generation: Option<u64>,
    pub policy_digest: PolicyDigest,
    pub operation_id: OperationId,
    pub teardown_failed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionMetadata {
    pub compacted_operations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableControlState {
    pub desired: DesiredState,
    pub operations: BTreeMap<OperationId, OperationRecord>,
    pub boot_connections: BTreeMap<ProfileId, BootConnection>,
    pub requested_resources: BTreeMap<ProfileId, RequestedResources>,
    pub last_connected_at: BTreeMap<ProfileId, SystemTime>,
    pub tombstones: BTreeMap<ProfileId, PersistedTombstone>,
    pub retention: RetentionMetadata,
    pub reconciliation_required: bool,
}

impl DurableControlState {
    /// Fence boot-local operation deadlines and derive reconnect intent from
    /// the current boot policy, never from the policy saved before reboot.
    pub fn prepare_for_reboot(&mut self) {
        self.desired.generation = self.desired.generation.saturating_add(1);
        for (profile_id, requested) in &mut self.desired.tunnels {
            *requested = if self.boot_connections.get(profile_id).is_some_and(|entry| {
                entry.enabled && entry.eligibility == BootEligibility::Eligible
            }) {
                RequestedTunnelState::Connected
            } else {
                RequestedTunnelState::Disconnected
            };
        }
        for operation in self.operations.values_mut() {
            if !operation.status.is_terminal() {
                operation.status = OperationStatus::Cancelled;
                operation.result = Some(OperationResult::Cancelled);
            }
        }
        self.reconciliation_required = true;
    }
}

/// Desired and operation facts recovered before the first startup scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredControlState {
    pub state: DurableControlState,
    pub same_boot: bool,
}

/// User-owned storage port. Implementations persist intent only; observed and
/// effective truth are deliberately absent from this interface.
pub trait ControlStateStore: fmt::Debug + Send + Sync + 'static {
    fn load(
        &self,
        current_boot_id: &str,
    ) -> Result<Option<RecoveredControlState>, ControlStateStoreError>;

    fn save(
        &self,
        current_boot_id: &str,
        state: &DurableControlState,
    ) -> Result<(), ControlStateStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlStateStoreError {
    #[error("unsupported persisted control-state schema version {0}")]
    UnsupportedSchema(u16),
    #[error("persisted control state is corrupt")]
    Corrupt,
    #[error("persisted control state exceeds its fixed capacity")]
    Capacity,
    #[error("persisted control state is not a private owner-controlled file")]
    UnsafeFile,
    #[error("persisted control state is invalid: {0}")]
    Invalid(String),
    #[error("persisted control state I/O failed: {0}")]
    Io(String),
}
