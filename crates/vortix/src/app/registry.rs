//! Render cache the dashboard reads: the engine's latest tunnel projection,
//! plus the route-conflict rule every surface shares.

use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::profile::ProfileId;
use crate::tunnel::{Connection, ConnectionHealth};

/// Per-tunnel role derived from declared `AllowedIPs` + current primary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Role {
    /// Owns the kernel default route. Carries the declared `AllowedIPs` for
    /// display / Security Guard scoping.
    Primary { allowed_ips: Vec<Cidr> },
    /// Reachable for its declared `AllowedIPs`; doesn't claim the default route.
    Addressable { allowed_ips: Vec<Cidr> },
    /// Declared `0/0` but another tunnel currently holds the default route —
    /// either because of a takeover race or because the user connected this
    /// one without `--force` and it landed second.
    AddressableSuppressed { allowed_ips: Vec<Cidr> },
    /// Reconnecting; the inner role is the one this tunnel held before the
    /// link went down (so the UI can render "Reconnecting (was Primary)").
    Reconnecting { prior_role: Box<Role> },
    /// Mid-connect prompt (2FA, passphrase) — role unknown until the prompt
    /// resolves.
    AwaitingInput,
}

/// Read-only view of one FSM. UI panels read through these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelSnapshot {
    pub profile_id: ProfileId,
    pub state: Connection,
    pub role: Role,
    pub health: ConnectionHealth,
    pub interface_name: Option<String>,
    pub started_at: Option<SystemTime>,
}

/// What kind of conflict `detect_conflict` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Conflict {
    /// Two profiles both claim the kernel default route. The `current` holder
    /// may be either Connected (already on the route) or Connecting (claimed
    /// it but `tunnel.up` hasn't returned yet — the §7.3 in-flight rule).
    DefaultRouteTakeover { current: ProfileId, new: ProfileId },
    /// Non-default-route overlap. Reserved for the future v2 conflict surface
    ///; not produced by the v1
    /// `detect_conflict` which only inspects the default route.
    RouteOverlap {
        with: ProfileId,
        overlapping_cidrs: Vec<Cidr>,
    },
}

/// Whether two route sets collide, and how.
///
/// Admission, the dashboard overlay and the CLI gate all have to answer this
/// identically: if they disagree, one refuses a connect another will not offer
/// to confirm. They each used to carry their own copy of the rule.
///
/// A default route intersects every other route, so it is only ever compared
/// against another default. That question is asked first; everything after it
/// is about specific destinations. A split tunnel alongside a full one is
/// legitimate — the more specific prefix wins, which is the point of running
/// both.
#[must_use]
pub fn classify_route_conflict(
    requested: &[Cidr],
    existing: &[Cidr],
    existing_profile: &ProfileId,
    requested_profile: &ProfileId,
) -> Option<Conflict> {
    let specific = |routes: &[Cidr]| {
        routes
            .iter()
            .filter(|route| route.prefix_len != 0)
            .copied()
            .collect::<Vec<_>>()
    };
    let claims_default = |routes: &[Cidr]| routes.iter().any(|route| route.prefix_len == 0);

    if claims_default(requested) && claims_default(existing) {
        return Some(Conflict::DefaultRouteTakeover {
            current: existing_profile.clone(),
            new: requested_profile.clone(),
        });
    }
    let overlapping_cidrs =
        crate::cidr::overlapping_cidrs(&specific(requested), &specific(existing));
    (!overlapping_cidrs.is_empty()).then(|| Conflict::RouteOverlap {
        with: existing_profile.clone(),
        overlapping_cidrs,
    })
}

/// What the dashboard renders, fed only by engine snapshots.
#[derive(Debug, Default)]
pub struct TunnelRegistry {
    tunnels: BTreeMap<ProfileId, TunnelSnapshot>,
    primary: Option<ProfileId>,
    default_route_interface: Option<String>,
}

impl TunnelRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }

    #[must_use]
    pub fn primary(&self) -> Option<&ProfileId> {
        self.primary.as_ref()
    }

    #[must_use]
    pub fn snapshot(&self, profile_id: &ProfileId) -> Option<TunnelSnapshot> {
        self.tunnels.get(profile_id).cloned()
    }

    /// Every tunnel, in stable profile order so panels do not flicker.
    #[must_use]
    pub fn snapshot_all(&self) -> Vec<TunnelSnapshot> {
        self.tunnels.values().cloned().collect()
    }

    pub fn replace_control_projection(
        &mut self,
        tunnels: &BTreeMap<ProfileId, TunnelSnapshot>,
        primary: Option<ProfileId>,
    ) {
        self.tunnels.clone_from(tunnels);
        self.primary = primary;
    }

    pub fn feed_default_route_interface(&mut self, interface: Option<String>) {
        self.default_route_interface = interface;
    }

    #[must_use]
    pub fn default_route_interface(&self) -> Option<&str> {
        self.default_route_interface.as_deref()
    }

    /// Put one tunnel in the cache directly; renderer tests only.
    #[cfg(test)]
    pub fn insert_for_test(&mut self, snapshot: TunnelSnapshot) {
        self.tunnels.insert(snapshot.profile_id.clone(), snapshot);
    }
}
