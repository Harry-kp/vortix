//! Immutable state published by the canonical control owner.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::vortix_core::cidr::Cidr;
use crate::vortix_core::control::model::{
    ChallengeId, ChallengeRecord, DesiredState, EffectiveState, ObservedState, OperationId,
    OperationRecord,
};
use crate::vortix_core::control::ControlDiagnosticView;
use crate::vortix_core::engine::registry::{Conflict, TunnelSnapshot};
use crate::vortix_core::engine::state::Connection;
use crate::vortix_core::profile::ProfileId;

/// Live admission readiness owned by the canonical service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceReadiness {
    pub reconciliation_complete: bool,
    pub authority_verified: bool,
}

/// Canonical system-DNS posture for the active primary tunnel.
///
/// This projection deliberately covers the operating system resolver path,
/// not application-specific encrypted DNS such as browser `DoH`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSecurityStatus {
    /// No primary tunnel currently owns the default route.
    #[default]
    NotActive,
    /// The primary tunnel did not request a VPN-wide resolver policy.
    NotRequested,
    /// Resolver intent exists, but current-generation readback is incomplete.
    Unverified,
    /// Exact resolver policy and every resolver's tunnel route were verified.
    Protected,
}

/// Resolver intent and proof state published by the canonical control owner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSecurityProjection {
    /// Resolver addresses intended for the active primary tunnel.
    pub intended_servers: Vec<IpAddr>,
    pub status: DnsSecurityStatus,
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
    /// Exact conflicts discovered only after a protocol completed negotiation.
    /// They remain available after the unaccepted tunnel is compensated so a
    /// client can explain the failure and submit the canonical acknowledgement.
    #[serde(default)]
    pub pending_route_conflicts: BTreeMap<ProfileId, Conflict>,
    /// Most recent authenticated, successfully completed connection for each
    /// stable profile identity. Clients render this projection but never
    /// derive or persist it themselves.
    #[serde(default)]
    pub last_connected_at: BTreeMap<ProfileId, SystemTime>,
    /// Canonical system-DNS intent and verified tunnel-path posture.
    #[serde(default)]
    pub dns: DnsSecurityProjection,
    pub operations: BTreeMap<OperationId, OperationRecord>,
    pub challenges: BTreeMap<ChallengeId, ChallengeRecord>,
    /// Redacted, bounded troubleshooting evidence. It is never an authority,
    /// protection, enrollment, or cleanup input.
    #[serde(default)]
    pub diagnostics: ControlDiagnosticView,
}

impl ControlSnapshot {
    /// Return the exact conflict a client must acknowledge before connecting
    /// `profile_id`. The calculation uses only canonical snapshot data.
    #[must_use]
    pub fn topology_conflict(&self, profile_id: &ProfileId) -> Option<Conflict> {
        if let Some(conflict) = self
            .pending_route_conflicts
            .get(profile_id)
            .filter(|conflict| self.conflict_peer_is_active(profile_id, conflict))
        {
            return Some(conflict.clone());
        }
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

    fn conflict_peer_is_active(&self, profile_id: &ProfileId, conflict: &Conflict) -> bool {
        let peer = match conflict {
            Conflict::DefaultRouteTakeover { current, new } if new == profile_id => current,
            Conflict::RouteOverlap { with, .. } => with,
            Conflict::DefaultRouteTakeover { .. } => return false,
        };
        self.tunnels
            .get(peer)
            .is_some_and(|tunnel| !matches!(tunnel.state, Connection::Disconnected { .. }))
    }
}
