//! Wire-independent privileged-operation and ownership contracts.
//!
//! This module is a pure security boundary. It defines what a future helper
//! may be asked to do and what it may attest, but contains no transport,
//! subprocess execution, root calls, profile parsing, or lifecycle hooks.

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;
use std::net::IpAddr;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

pub(super) const MAX_RESOURCE_ITEMS: usize = 256;
pub(super) const CONTRACT_SCHEMA_VERSION: u16 = 2;

/// Allocation-bounded sequence decoder for every collection crossing the
/// untrusted privileged wire. It rejects the first element beyond `LIMIT`
/// instead of first allocating an attacker-sized `Vec` and validating later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BoundedVec<T, const LIMIT: usize>(Vec<T>);

impl<T, const LIMIT: usize> BoundedVec<T, LIMIT> {
    pub(super) fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<'de, T, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVisitor<T, const LIMIT: usize>(PhantomData<T>);

        impl<'de, T, const LIMIT: usize> Visitor<'de> for BoundedVisitor<T, LIMIT>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {LIMIT} items")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(LIMIT);
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = sequence.next_element()? {
                    if values.len() == LIMIT {
                        return Err(serde::de::Error::invalid_length(
                            LIMIT.saturating_add(1),
                            &self,
                        ));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor(PhantomData))
    }
}

pub(super) fn has_duplicates<'a, T: Ord + 'a>(values: impl IntoIterator<Item = &'a T>) -> bool {
    let mut unique = BTreeSet::new();
    values.into_iter().any(|value| !unique.insert(value))
}

pub(super) fn invalid_unicast_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_multicast() || address.is_broadcast()
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

mod child_owner;
mod ledger;
mod operation;
mod protocol_plan;
mod receipt;
mod resource;

pub(crate) use child_owner::ChildSpawnAuthority;
pub use child_owner::{
    ChildExit, ChildObservation, ChildOwner, ChildOwnershipError, ChildOwnershipState,
    ContainmentId, CustodianAction, ObservedChildIdentity, OwnedChild, StandardCustodianContract,
};
pub(crate) use ledger::{HelperLedgerRecord, HelperLedgerResource, HelperResourceState};
pub(crate) use operation::PlatformVerifiedAuthority;
pub use operation::{
    BootScope, HelperEpoch, LeaseId, NetworkPolicyOperation, OperationAdmission, OperationDigest,
    OperationError, OperationGuard, PeerProcessIdentity, PolicyDigest, PolicyPhase,
    PolicyPredecessor, PrivilegedDnsAssignment, PrivilegedDnsScope, PrivilegedOperation,
    PrivilegedOperationId, PrivilegedRequest, ReplayBaseline, ReplayHighWater, ReplayRecord,
    ReplayUnused, RequestSequence, RootAuthorityLedger, ScopedRoute, ServiceInstanceClaim,
    ServiceManager, TrustedDaemonPrincipal,
};
pub use protocol_plan::{
    DnsHostname, OpenVpnAuthFactors, OpenVpnChallengeKind, OpenVpnPlan, OpenVpnRemote,
    OpenVpnRemoteSelection, OpenVpnRoute, OpenVpnTransport, ProfileMaterialRef,
    ProfileMaterialSlot, ProtocolEndpoint, ProtocolPlan, ProtocolPlanError,
    WireGuardInterfaceOptions, WireGuardPeerPlan, WireGuardPlan, WireGuardPresharedKeyRef,
};
pub(crate) use receipt::AuthenticatedReceiptVerifier;
pub use receipt::{
    AmbiguousPhase, ObservationState, ReceiptError, ReceiptLedger, ReceiptOutcome, RejectionCode,
    ResourceObservation, ResourceOwnership, UntrustedReceipt, VerifiedReceipt,
};
pub use resource::{ResourceError, ResourceKind, ResourceObservationTarget, ResourceTag};
