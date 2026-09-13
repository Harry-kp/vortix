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
            // `?` here returned `None` from the whole function — "no conflict
            // with anyone" — the moment a single peer had no route entry,
            // hiding every other peer's conflict behind it. One peer we cannot
            // describe is a peer to skip, not an answer about the rest.
            let Some(existing) = self.profile_routes.get(existing_id) else {
                continue;
            };
            let requested_default = requested.iter().any(|route| route.prefix_len == 0);
            let existing_default = existing.iter().any(|route| route.prefix_len == 0);
            if requested_default && existing_default {
                return Some(Conflict::DefaultRouteTakeover {
                    current: existing_id.clone(),
                    new: profile_id.clone(),
                });
            }
            // A default route intersects every other route by definition, so
            // comparing it here reported a full tunnel joining a split tunnel
            // as a "Route Overlap" — a conflict the user cannot act on,
            // because nothing is actually contended. Whether two profiles both
            // want the default is the question asked immediately above; this
            // one is only about specific destinations colliding. A split
            // tunnel alongside a full one is legitimate: the more specific
            // prefix wins, which is the point of running both.
            let overlapping_cidrs = requested
                .iter()
                .filter(|route| route.prefix_len != 0)
                .filter(|route| {
                    existing
                        .iter()
                        .any(|current| current.prefix_len != 0 && route.intersects(current))
                })
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

#[cfg(test)]
mod conflict_scan_tests {
    use super::*;
    use crate::vortix_core::engine::registry::Role;
    use crate::vortix_core::engine::state::{ConnectionHealth, DetailedConnectionInfo};

    fn connected(profile_id: &ProfileId) -> TunnelSnapshot {
        TunnelSnapshot {
            profile_id: profile_id.clone(),
            state: Connection::Connected {
                profile_id: profile_id.clone(),
                since: SystemTime::UNIX_EPOCH,
                health: ConnectionHealth::default(),
                details: Box::new(DetailedConnectionInfo::default()),
            },
            role: Role::Addressable {
                allowed_ips: Vec::new(),
            },
            health: ConnectionHealth::default(),
            interface_name: None,
            started_at: None,
        }
    }

    fn cidr(value: &str) -> Cidr {
        value.parse().expect("valid cidr")
    }

    /// A peer Vortix cannot describe is a peer to skip, not an answer about
    /// every other peer. The scan used `?` on the peer lookup, so one tunnel
    /// with no recorded routes returned "no conflict anywhere" — and a real
    /// default-route takeover sitting behind it in the map was never seen.
    #[test]
    fn a_peer_without_routes_does_not_hide_a_conflict_behind_it() {
        let undescribed = ProfileId::new("aaa-no-routes");
        let holder = ProfileId::new("zzz-holds-default");
        let candidate = ProfileId::new("candidate");

        let mut snapshot = ControlSnapshot::default();
        snapshot
            .tunnels
            .insert(undescribed.clone(), connected(&undescribed));
        snapshot.tunnels.insert(holder.clone(), connected(&holder));
        // `undescribed` deliberately has no profile_routes entry, and sorts
        // before `holder` in the BTreeMap, so it is scanned first.
        snapshot
            .profile_routes
            .insert(holder.clone(), vec![cidr("0.0.0.0/0")]);
        snapshot
            .profile_routes
            .insert(candidate.clone(), vec![cidr("0.0.0.0/0")]);

        assert_eq!(
            snapshot.topology_conflict(&candidate),
            Some(Conflict::DefaultRouteTakeover {
                current: holder,
                new: candidate,
            }),
            "the conflict with a fully described peer must still be reported"
        );
    }

    /// The reported case: `wg07` is a split tunnel
    /// (`10.200.0.0/24, 10.250.0.0/24`) and `wg08` is a full tunnel
    /// (`0.0.0.0/0`). Connecting the second alongside the first raised "Route
    /// Overlap", because a default route intersects every other route by
    /// definition. Nothing is contended — the more specific prefix wins — so
    /// there is no conflict to confirm in either direction.
    #[test]
    fn a_full_tunnel_and_a_split_tunnel_do_not_overlap() {
        let split = ProfileId::new("wg07-split");
        let full = ProfileId::new("wg08-full");

        let mut snapshot = ControlSnapshot::default();
        snapshot.profile_routes.insert(
            split.clone(),
            vec![cidr("10.200.0.0/24"), cidr("10.250.0.0/24")],
        );
        snapshot
            .profile_routes
            .insert(full.clone(), vec![cidr("0.0.0.0/0")]);

        snapshot.tunnels.insert(split.clone(), connected(&split));
        assert_eq!(
            snapshot.topology_conflict(&full),
            None,
            "a full tunnel joining a split tunnel claims nothing the split tunnel holds"
        );

        snapshot.tunnels.clear();
        snapshot.tunnels.insert(full.clone(), connected(&full));
        assert_eq!(
            snapshot.topology_conflict(&split),
            None,
            "a split tunnel joining a full tunnel takes only its own prefixes"
        );
    }

    /// The exclusion is scoped to default routes only. Two split tunnels that
    /// genuinely claim the same destination must still be caught, and two full
    /// tunnels must still ask for a takeover.
    #[test]
    fn specific_prefixes_and_two_defaults_still_conflict() {
        let held = ProfileId::new("aaa-held");
        let candidate = ProfileId::new("bbb-candidate");

        let mut snapshot = ControlSnapshot::default();
        snapshot.tunnels.insert(held.clone(), connected(&held));
        snapshot
            .profile_routes
            .insert(held.clone(), vec![cidr("10.250.0.0/24")]);
        snapshot
            .profile_routes
            .insert(candidate.clone(), vec![cidr("10.250.0.0/24")]);
        assert_eq!(
            snapshot.topology_conflict(&candidate),
            Some(Conflict::RouteOverlap {
                with: held.clone(),
                overlapping_cidrs: vec![cidr("10.250.0.0/24")],
            }),
            "two profiles claiming the same specific prefix still collide"
        );

        snapshot
            .profile_routes
            .insert(held.clone(), vec![cidr("0.0.0.0/0")]);
        snapshot
            .profile_routes
            .insert(candidate.clone(), vec![cidr("0.0.0.0/0")]);
        assert_eq!(
            snapshot.topology_conflict(&candidate),
            Some(Conflict::DefaultRouteTakeover {
                current: held,
                new: candidate,
            }),
            "two full tunnels still need the takeover confirmation"
        );
    }
}
