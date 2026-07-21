//! Pure, level-triggered reconciliation planning.

use std::collections::{BTreeMap, BTreeSet};

use crate::vortix_core::control::worker::ControlRevision;
use crate::vortix_core::ports::tunnel::AdoptionEvidence;
use crate::vortix_core::profile::ProfileId;

/// Why an observed tunnel can (or cannot) be controlled by Vortix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationOwnership {
    /// A protocol worker produced the handle for the exact revision.
    Managed,
    /// Protocol metadata names one profile, but no typed attestation exists.
    ExternalUnambiguous,
    /// Heuristic or ambiguous scanner evidence. Never primary/retry eligible.
    UnknownExternal,
}

/// Scanner certainty is distinct from tunnel presence. Probe failures and
/// partial snapshots never masquerade as absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEvidence {
    ConfirmedPresent,
    ConfirmedAbsent,
    ProbeFailed,
    MissingPartial,
}

impl ScanEvidence {
    #[must_use]
    pub const fn is_fresh_presence(self) -> bool {
        matches!(self, Self::ConfirmedPresent)
    }
    #[must_use]
    pub const fn is_fresh_absence(self) -> bool {
        matches!(self, Self::ConfirmedAbsent)
    }
}

/// One complete observer fact for a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelObservation {
    pub evidence: ScanEvidence,
    pub interface_name: Option<String>,
    pub ownership: ObservationOwnership,
    /// Exact protocol-authoritative fence. Managed facts without this tuple
    /// are stale and cannot establish convergence.
    pub revision: Option<ControlRevision>,
    /// Only a protocol adapter can issue this attestation. Scanner guesses do
    /// not become managed merely because profile/interface strings match.
    pub adoption: Option<AdoptionEvidence>,
    pub observed_at_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightMutation {
    pub revision: ControlRevision,
    pub operation: crate::vortix_core::control::model::OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectTombstone {
    pub revision: ControlRevision,
    /// A failed or ambiguous teardown remains retry eligible while the
    /// tombstone continues to suppress scanner adoption.
    pub teardown_failed: bool,
}

/// One complete level-triggered input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileInput {
    pub revision: ControlRevision,
    pub desired_connected: BTreeSet<ProfileId>,
    pub observations: BTreeMap<ProfileId, TunnelObservation>,
    pub in_flight: BTreeMap<ProfileId, InFlightMutation>,
    pub disconnect_tombstones: BTreeMap<ProfileId, DisconnectTombstone>,
}

/// Side-effect-free intent emitted by the planner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    Connect {
        profile_id: ProfileId,
        revision: ControlRevision,
    },
    Disconnect {
        profile_id: ProfileId,
        revision: ControlRevision,
    },
    CleanupStaleManaged {
        profile_id: ProfileId,
        stale_revision: Option<ControlRevision>,
        target_revision: ControlRevision,
    },
    ObserveReadOnly {
        profile_id: ProfileId,
        interface_name: Option<String>,
    },
    AdoptAttested {
        profile_id: ProfileId,
        evidence: AdoptionEvidence,
        revision: ControlRevision,
    },
    ClearTombstone {
        profile_id: ProfileId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub revision: ControlRevision,
    pub actions: Vec<ReconcileAction>,
}

/// Compute a complete reconciliation plan without performing side effects.
#[must_use]
pub fn plan_reconciliation(input: &ReconcileInput) -> ReconcilePlan {
    let mut actions = Vec::new();
    let profiles = input
        .desired_connected
        .iter()
        .chain(input.observations.keys())
        .chain(input.disconnect_tombstones.keys())
        .chain(input.in_flight.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    for profile_id in profiles {
        let desired = input.desired_connected.contains(&profile_id);
        let observed = input.observations.get(&profile_id);
        let in_flight = input.in_flight.get(&profile_id);

        if let Some(tombstone) = input.disconnect_tombstones.get(&profile_id) {
            if observed.is_some_and(|fact| fact.evidence.is_fresh_absence()) {
                actions.push(ReconcileAction::ClearTombstone { profile_id });
            } else if tombstone.teardown_failed && in_flight.is_none() {
                actions.push(ReconcileAction::Disconnect {
                    profile_id,
                    revision: input.revision.clone(),
                });
            }
            continue;
        }

        let exact_in_flight = in_flight.is_some_and(|mutation| mutation.revision == input.revision);
        if in_flight.is_some() && !exact_in_flight {
            actions.push(ReconcileAction::CleanupStaleManaged {
                profile_id,
                stale_revision: in_flight.map(|mutation| mutation.revision.clone()),
                target_revision: input.revision.clone(),
            });
            continue;
        }

        match observed {
            Some(fact) if fact.evidence.is_fresh_presence() => {
                let exact_managed = fact.ownership == ObservationOwnership::Managed
                    && fact.revision.as_ref() == Some(&input.revision);
                if fact.ownership == ObservationOwnership::Managed && !exact_managed {
                    actions.push(ReconcileAction::CleanupStaleManaged {
                        profile_id,
                        stale_revision: fact.revision.clone(),
                        target_revision: input.revision.clone(),
                    });
                } else if exact_in_flight {
                    // Scanner presence cannot complete protocol work.
                } else if exact_managed && !desired {
                    actions.push(ReconcileAction::Disconnect {
                        profile_id,
                        revision: input.revision.clone(),
                    });
                } else if !exact_managed {
                    if let Some(evidence) = fact.adoption.clone().filter(|evidence| {
                        evidence.profile_id() == &profile_id
                            && Some(evidence.interface_name()) == fact.interface_name.as_deref()
                    }) {
                        actions.push(ReconcileAction::AdoptAttested {
                            profile_id,
                            evidence,
                            revision: input.revision.clone(),
                        });
                    } else {
                        actions.push(ReconcileAction::ObserveReadOnly {
                            profile_id,
                            interface_name: fact.interface_name.clone(),
                        });
                    }
                }
            }
            Some(fact)
                if matches!(
                    fact.evidence,
                    ScanEvidence::ProbeFailed | ScanEvidence::MissingPartial
                ) =>
            {
                // Unknown evidence is never convergence or teardown proof.
                if fact.ownership != ObservationOwnership::Managed {
                    actions.push(ReconcileAction::ObserveReadOnly {
                        profile_id,
                        interface_name: fact.interface_name.clone(),
                    });
                }
            }
            _ if desired && !exact_in_flight => actions.push(ReconcileAction::Connect {
                profile_id,
                revision: input.revision.clone(),
            }),
            _ => {}
        }
    }
    ReconcilePlan {
        revision: input.revision.clone(),
        actions,
    }
}

/// Merge scanner evidence without overwriting protocol-authoritative identity.
pub fn merge_observation(
    current: &mut TunnelObservation,
    scanner: TunnelObservation,
    in_flight: Option<&ControlRevision>,
) {
    if in_flight.is_some()
        || current.ownership == ObservationOwnership::Managed
            && current.revision.is_some()
            && scanner.ownership != ObservationOwnership::Managed
    {
        current.evidence = scanner.evidence;
        current.observed_at_millis = scanner.observed_at_millis;
        return;
    }
    *current = scanner;
}
