//! Immutable state published by the canonical control owner.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::model::{
    ChallengeId, ChallengeRecord, DesiredState, EffectiveState, ObservedState, OperationId,
    OperationRecord,
};
use crate::vortix_core::engine::registry::{Conflict, TunnelSnapshot};
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::profile::ProfileId;

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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ControlSnapshot {
    /// Monotonically increasing publication generation.
    pub generation: u64,
    pub readiness: ServiceReadiness,
    pub desired: DesiredState,
    pub observed: ObservedState,
    pub effective: EffectiveState,
    /// Complete immutable renderer projection owned by the control service.
    /// Clients may cache it, but must not re-derive lifecycle or role truth.
    #[serde(default)]
    pub tunnels: BTreeMap<ProfileId, TunnelSnapshot>,
    /// Profile whose authoritative interface owns the observed kernel default
    /// route. `None` is an honest split-only/no-primary state.
    #[serde(default)]
    pub primary: Option<ProfileId>,
    /// Canonical route claims for every managed profile, including profiles
    /// that are currently disconnected. TUI clients use this read-only data
    /// for preflight overlays and never parse protocol configuration.
    #[serde(default)]
    pub profile_routes: BTreeMap<ProfileId, Vec<Cidr>>,
    pub operations: BTreeMap<OperationId, OperationRecord>,
    pub challenges: BTreeMap<ChallengeId, ChallengeRecord>,
}

impl ControlSnapshot {
    /// Return the exact conflict a client must acknowledge before connecting
    /// `profile_id`. The calculation uses only canonical snapshot data.
    #[must_use]
    pub fn topology_conflict(&self, profile_id: &ProfileId) -> Option<Conflict> {
        let requested = self.profile_routes.get(profile_id)?;
        for (existing_id, tunnel) in &self.tunnels {
            if existing_id == profile_id || matches!(tunnel.state, Connection::Disconnected { .. })
            {
                continue;
            }
            let existing = self.profile_routes.get(existing_id)?;
            let requested_default = requested.iter().any(|route| route.prefix_len == 0);
            let existing_default = existing.iter().any(|route| route.prefix_len == 0);
            if requested_default && existing_default {
                return Some(Conflict::DefaultRouteTakeover {
                    current: existing_id.clone(),
                    new: profile_id.clone(),
                });
            }
            let overlapping_cidrs = requested
                .iter()
                .filter(|route| existing.iter().any(|current| route.intersects(current)))
                .copied()
                .collect::<Vec<_>>();
            if !overlapping_cidrs.is_empty() {
                return Some(Conflict::RouteOverlap {
                    with: existing_id.clone(),
                    overlapping_cidrs,
                });
            }
        }
        None
    }
}
