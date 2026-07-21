//! Immutable state published by the canonical control owner.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::vortix_core::control::model::{
    ChallengeId, ChallengeRecord, DesiredState, EffectiveState, ObservedState, OperationId,
    OperationRecord,
};

/// Live admission readiness owned by the canonical service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceReadiness {
    pub reconciliation_complete: bool,
    pub authority_verified: bool,
}

impl Default for ServiceReadiness {
    fn default() -> Self {
        Self {
            reconciliation_complete: true,
            authority_verified: true,
        }
    }
}

/// Complete bounded view consumed by CLI/TUI clients.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlSnapshot {
    /// Monotonically increasing publication generation.
    pub generation: u64,
    pub readiness: ServiceReadiness,
    pub desired: DesiredState,
    pub observed: ObservedState,
    pub effective: EffectiveState,
    pub operations: BTreeMap<OperationId, OperationRecord>,
    pub challenges: BTreeMap<ChallengeId, ChallengeRecord>,
}
