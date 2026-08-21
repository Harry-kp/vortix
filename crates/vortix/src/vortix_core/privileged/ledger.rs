//! Strict, bounded root-owned helper ledger envelope.

use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::vortix_core::cidr::Cidr;

use super::{
    has_duplicates, invalid_unicast_ip, BoundedVec, HelperEpoch, ObservedChildIdentity,
    OperationError, PolicyDigest, PolicyProjection, ReplayRecord, RequestSequence, ResourceKind,
    ResourceTag, MAX_RESOURCE_ITEMS,
};

const HELPER_LEDGER_SCHEMA_VERSION: u16 = 12;
const MAX_PHYSICAL_DNS_VALUE_BYTES: usize = 253;
const MAX_PHYSICAL_DNS_RECORD_BYTES: usize = 64 * 1024;
const MAX_ROUTE_INTERFACE_BYTES: usize = 15;
pub(crate) const MAX_HELPER_LEDGER_BYTES: u64 = 64 * 1024;

#[derive(Default)]
struct BoundedLedgerWriter {
    encoded_bytes: u64,
}

impl std::io::Write for BoundedLedgerWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let encoded_bytes = self
            .encoded_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if encoded_bytes > MAX_HELPER_LEDGER_BYTES {
            return Err(std::io::Error::other("helper ledger capacity exceeded"));
        }
        self.encoded_bytes = encoded_bytes;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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

/// Fixed kernel route backends selected by the helper. Callers cannot supply
/// a table, command, executable, or platform handle through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalRouteBackend {
    /// Legacy protocol-owned Linux routes. Never valid as helper ownership.
    LinuxIpMain,
    /// Fixed Vortix policy table, packet mark, and rule set (schema v1).
    LinuxPolicyV1,
    /// Legacy protocol-owned macOS routes. Never valid as helper ownership.
    MacOsRouteTable,
    /// Fixed Vortix-scoped macOS route set (schema v1).
    MacOsScopedV1,
}

impl PhysicalRouteBackend {
    const fn supports_helper_ownership(self) -> bool {
        matches!(self, Self::LinuxPolicyV1 | Self::MacOsScopedV1)
    }
}

/// Helper-minted identity for one durable route replacement transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RouteTransactionId([u8; 32]);

impl RouteTransactionId {
    #[allow(
        dead_code,
        reason = "minted only after the atomic protocol-to-policy route ownership cutover"
    )]
    pub(crate) fn new(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0; 32] {
            Err("route transaction identity must be non-zero")
        } else {
            Ok(Self(bytes))
        }
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// One fully resolved route persisted before the helper mutates the kernel.
/// Symbolic protocol gateways are resolved before this boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalRouteEntry {
    destination: Cidr,
    interface: String,
    gateway: Option<IpAddr>,
    metric: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalRouteEntryWire {
    destination: Cidr,
    interface: String,
    gateway: Option<IpAddr>,
    metric: Option<u32>,
}

impl<'de> Deserialize<'de> for PhysicalRouteEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PhysicalRouteEntryWire::deserialize(deserializer)?;
        Self::new(wire.destination, wire.interface, wire.gateway, wire.metric)
            .map_err(serde::de::Error::custom)
    }
}

impl PhysicalRouteEntry {
    pub(crate) fn new(
        destination: Cidr,
        interface: String,
        gateway: Option<IpAddr>,
        metric: Option<u32>,
    ) -> Result<Self, &'static str> {
        if !destination.is_valid()
            || destination.canonical_network() != destination
            || !valid_route_interface(&interface)
            || gateway.is_some_and(|gateway| {
                invalid_unicast_ip(&gateway) || gateway.is_ipv4() != destination.is_v4()
            })
        {
            return Err("physical route entry is invalid");
        }
        Ok(Self {
            destination,
            interface,
            gateway,
            metric,
        })
    }

    pub(crate) const fn destination(&self) -> Cidr {
        self.destination
    }

    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    pub(crate) const fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }

    pub(crate) const fn metric(&self) -> Option<u32> {
        self.metric
    }
}

fn valid_route_interface(interface: &str) -> bool {
    !interface.is_empty()
        && interface.len() <= MAX_ROUTE_INTERFACE_BYTES
        && interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Durable phase of an exact route transaction. The route writer is not
/// activated merely by the presence of this type; activation separately
/// requires the network-policy capability and the protocol ownership cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalRouteStage {
    Prepared,
    EffectPendingObservation,
    ObservedOwned,
    ObservedAbsent,
    Superseded,
    OwnedReleasePending,
    AbsentReleasePending,
    SupersededReleasePending,
}

/// Root-owned binding between one logical route projection and the exact
/// platform entries that must be observed, rolled back, or released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HelperLedgerRoutes {
    resource: ResourceTag,
    backend: PhysicalRouteBackend,
    transaction_id: RouteTransactionId,
    intended_digest: PolicyDigest,
    stage: PhysicalRouteStage,
    entries: Vec<PhysicalRouteEntry>,
    transport_bypass_targets: Vec<IpAddr>,
    transport_bypass_entries: Vec<PhysicalRouteEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerRoutesWire {
    resource: ResourceTag,
    backend: PhysicalRouteBackend,
    transaction_id: RouteTransactionId,
    intended_digest: PolicyDigest,
    stage: PhysicalRouteStage,
    entries: BoundedVec<PhysicalRouteEntry, MAX_RESOURCE_ITEMS>,
    transport_bypass_targets: BoundedVec<IpAddr, MAX_RESOURCE_ITEMS>,
    transport_bypass_entries: BoundedVec<PhysicalRouteEntry, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperLedgerRoutes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HelperLedgerRoutesWire::deserialize(deserializer)?;
        let value = Self {
            resource: wire.resource,
            backend: wire.backend,
            transaction_id: wire.transaction_id,
            intended_digest: wire.intended_digest,
            stage: wire.stage,
            entries: wire.entries.into_vec(),
            transport_bypass_targets: wire.transport_bypass_targets.into_vec(),
            transport_bypass_entries: wire.transport_bypass_entries.into_vec(),
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl HelperLedgerRoutes {
    #[allow(
        dead_code,
        reason = "persisted only after the atomic protocol-to-policy route ownership cutover"
    )]
    pub(crate) fn prepared(
        resource: ResourceTag,
        backend: PhysicalRouteBackend,
        transaction_id: RouteTransactionId,
        intended_digest: PolicyDigest,
        entries: Vec<PhysicalRouteEntry>,
        transport_bypass_targets: Vec<IpAddr>,
        transport_bypass_entries: Vec<PhysicalRouteEntry>,
    ) -> Result<Self, &'static str> {
        let value = Self {
            resource,
            backend,
            transaction_id,
            intended_digest,
            stage: PhysicalRouteStage::Prepared,
            entries,
            transport_bypass_targets,
            transport_bypass_entries,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), &'static str> {
        let mut destinations = std::collections::HashSet::with_capacity(self.entries.len());
        let mut bypass_targets =
            std::collections::HashSet::with_capacity(self.transport_bypass_targets.len());
        let mut bypass_destinations =
            std::collections::HashSet::with_capacity(self.transport_bypass_entries.len());
        let host_destination = |target: IpAddr| {
            Cidr::new(target, if target.is_ipv4() { 32 } else { 128 })
                .expect("an IP address always forms a host CIDR")
        };
        if self.resource.kind() != ResourceKind::Routes
            || !self.backend.supports_helper_ownership()
            || self.transaction_id.is_zero()
            || self.entries.len() > MAX_RESOURCE_ITEMS
            || self.transport_bypass_targets.len() > MAX_RESOURCE_ITEMS
            || self.transport_bypass_entries.len() > MAX_RESOURCE_ITEMS
            || self
                .entries
                .iter()
                .any(|entry| !destinations.insert(entry.destination()))
            || self
                .transport_bypass_targets
                .iter()
                .any(|target| invalid_unicast_ip(target) || !bypass_targets.insert(*target))
            || self.transport_bypass_entries.iter().any(|entry| {
                !bypass_destinations.insert(entry.destination())
                    || !bypass_targets.contains(&entry.destination().addr)
                    || entry.destination() != host_destination(entry.destination().addr)
            })
            || match self.backend {
                PhysicalRouteBackend::LinuxPolicyV1 => !self.transport_bypass_entries.is_empty(),
                PhysicalRouteBackend::MacOsScopedV1 => {
                    self.transport_bypass_entries.len() != self.transport_bypass_targets.len()
                }
                PhysicalRouteBackend::LinuxIpMain | PhysicalRouteBackend::MacOsRouteTable => true,
            }
        {
            return Err("physical route ownership is invalid");
        }
        Ok(())
    }

    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    pub(crate) const fn backend(&self) -> PhysicalRouteBackend {
        self.backend
    }

    pub(crate) const fn transaction_id(&self) -> RouteTransactionId {
        self.transaction_id
    }

    const fn transaction_id_ref(&self) -> &RouteTransactionId {
        &self.transaction_id
    }

    pub(crate) const fn intended_digest(&self) -> PolicyDigest {
        self.intended_digest
    }

    pub(crate) const fn stage(&self) -> PhysicalRouteStage {
        self.stage
    }

    pub(crate) fn entries(&self) -> &[PhysicalRouteEntry] {
        &self.entries
    }

    pub(crate) fn transport_bypass_targets(&self) -> &[IpAddr] {
        &self.transport_bypass_targets
    }

    pub(crate) fn transport_bypass_entries(&self) -> &[PhysicalRouteEntry] {
        &self.transport_bypass_entries
    }

    pub(crate) fn prepare_for(
        &self,
        projection: &PolicyProjection,
        entries: Vec<PhysicalRouteEntry>,
        transport_bypass_targets: Vec<IpAddr>,
        transport_bypass_entries: Vec<PhysicalRouteEntry>,
    ) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalRouteStage::ObservedOwned | PhysicalRouteStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("route projection does not match settled physical state");
        }
        Self::prepared(
            self.resource.clone(),
            self.backend,
            self.transaction_id,
            projection.digest(),
            entries,
            transport_bypass_targets,
            transport_bypass_entries,
        )
    }

    pub(crate) fn mark_effect_pending(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalRouteStage::Prepared {
            return Err("route effect requires prepared ownership");
        }
        self.stage = PhysicalRouteStage::EffectPendingObservation;
        Ok(self)
    }

    pub(crate) fn confirm_observed(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if self.stage != PhysicalRouteStage::EffectPendingObservation
            || projection.policy() != &self.resource
            || projection.digest() != self.intended_digest
        {
            return Err("route observation requires a pending exact effect");
        }
        self.stage = settled_route_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn mark_release_pending(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalRouteStage::ObservedOwned => PhysicalRouteStage::OwnedReleasePending,
            PhysicalRouteStage::ObservedAbsent => PhysicalRouteStage::AbsentReleasePending,
            PhysicalRouteStage::Superseded => PhysicalRouteStage::SupersededReleasePending,
            _ => return Err("route release requires settled ownership"),
        };
        Ok(self)
    }

    pub(crate) fn supersede(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalRouteStage::ObservedOwned {
            return Err("only observed route ownership can be superseded");
        }
        self.stage = PhysicalRouteStage::Superseded;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_mutation(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalRouteStage::EffectPendingObservation
                | PhysicalRouteStage::ObservedOwned
                | PhysicalRouteStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("route rollback projection does not match physical state");
        }
        self.intended_digest = projection.digest();
        self.stage = settled_route_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_release(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalRouteStage::OwnedReleasePending => PhysicalRouteStage::ObservedOwned,
            PhysicalRouteStage::AbsentReleasePending => PhysicalRouteStage::ObservedAbsent,
            PhysicalRouteStage::SupersededReleasePending => PhysicalRouteStage::Superseded,
            _ => return Err("route release rollback requires pending release ownership"),
        };
        Ok(self)
    }
}

fn settled_route_stage(projection: &PolicyProjection) -> Result<PhysicalRouteStage, &'static str> {
    let PolicyProjection::Routes { routes, .. } = projection else {
        return Err("physical route state requires a route projection");
    };
    if routes.is_empty() {
        Ok(PhysicalRouteStage::ObservedAbsent)
    } else {
        Ok(PhysicalRouteStage::ObservedOwned)
    }
}

/// Physical firewall engines that the root helper may select. The daemon can
/// never supply an executable, table name, path, or argument vector through
/// this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalFirewallBackend {
    LinuxNft,
    LinuxIptablesDualFamily,
    MacOsPf,
}

/// Fixed-size helper-minted identity for one physical firewall transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct FirewallTransactionId([u8; 32]);

impl FirewallTransactionId {
    pub(crate) fn new(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0; 32] {
            Err("firewall transaction identity must be non-zero")
        } else {
            Ok(Self(bytes))
        }
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// Durable phase of one exact physical firewall transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalFirewallStage {
    Prepared,
    EffectPendingObservation,
    ObservedOwned,
    ObservedAbsent,
    Superseded,
    OwnedReleasePending,
    AbsentReleasePending,
    SupersededReleasePending,
}

/// Root-owned binding between one logical firewall projection and the exact
/// physical backend that must be audited, observed, updated, or released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HelperLedgerFirewall {
    resource: ResourceTag,
    backend: PhysicalFirewallBackend,
    transaction_id: FirewallTransactionId,
    intended_digest: PolicyDigest,
    stage: PhysicalFirewallStage,
}

impl HelperLedgerFirewall {
    pub(crate) const fn prepared(
        resource: ResourceTag,
        backend: PhysicalFirewallBackend,
        transaction_id: FirewallTransactionId,
        intended_digest: PolicyDigest,
    ) -> Self {
        Self {
            resource,
            backend,
            transaction_id,
            intended_digest,
            stage: PhysicalFirewallStage::Prepared,
        }
    }

    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    pub(crate) const fn backend(&self) -> PhysicalFirewallBackend {
        self.backend
    }

    pub(crate) const fn transaction_id(&self) -> FirewallTransactionId {
        self.transaction_id
    }

    const fn transaction_id_ref(&self) -> &FirewallTransactionId {
        &self.transaction_id
    }

    pub(crate) const fn intended_digest(&self) -> PolicyDigest {
        self.intended_digest
    }

    pub(crate) const fn stage(&self) -> PhysicalFirewallStage {
        self.stage
    }

    pub(crate) fn prepare_for(&self, projection: &PolicyProjection) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalFirewallStage::ObservedOwned | PhysicalFirewallStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("firewall projection does not match settled physical state");
        }
        Ok(Self::prepared(
            self.resource.clone(),
            self.backend,
            self.transaction_id,
            projection.digest(),
        ))
    }

    pub(crate) fn mark_effect_pending(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalFirewallStage::Prepared {
            return Err("firewall effect requires prepared ownership");
        }
        self.stage = PhysicalFirewallStage::EffectPendingObservation;
        Ok(self)
    }

    pub(crate) fn confirm_observed(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if self.stage != PhysicalFirewallStage::EffectPendingObservation
            || projection.policy() != &self.resource
            || projection.digest() != self.intended_digest
        {
            return Err("firewall observation requires a pending effect");
        }
        self.stage = settled_firewall_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn mark_release_pending(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalFirewallStage::ObservedOwned => PhysicalFirewallStage::OwnedReleasePending,
            PhysicalFirewallStage::ObservedAbsent => PhysicalFirewallStage::AbsentReleasePending,
            PhysicalFirewallStage::Superseded => PhysicalFirewallStage::SupersededReleasePending,
            _ => return Err("firewall release requires settled ownership"),
        };
        Ok(self)
    }

    pub(crate) fn supersede(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalFirewallStage::ObservedOwned {
            return Err("only observed firewall ownership can be superseded");
        }
        self.stage = PhysicalFirewallStage::Superseded;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_mutation(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalFirewallStage::EffectPendingObservation
                | PhysicalFirewallStage::ObservedOwned
                | PhysicalFirewallStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("firewall rollback projection does not match physical state");
        }
        self.intended_digest = projection.digest();
        self.stage = settled_firewall_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_release(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalFirewallStage::OwnedReleasePending => PhysicalFirewallStage::ObservedOwned,
            PhysicalFirewallStage::AbsentReleasePending => PhysicalFirewallStage::ObservedAbsent,
            PhysicalFirewallStage::SupersededReleasePending => PhysicalFirewallStage::Superseded,
            _ => return Err("firewall release rollback requires pending release ownership"),
        };
        Ok(self)
    }
}

fn settled_firewall_stage(
    projection: &PolicyProjection,
) -> Result<PhysicalFirewallStage, &'static str> {
    match projection.firewall_blocks() {
        Some(true) => Ok(PhysicalFirewallStage::ObservedOwned),
        Some(false) => Ok(PhysicalFirewallStage::ObservedAbsent),
        None => Err("physical firewall state requires a firewall projection"),
    }
}

/// Physical DNS engines whose prior state can be captured before mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalDnsBackend {
    LinuxResolved,
    LinuxResolvconf,
    MacOsResolverFiles,
}

/// Helper-minted identity for one durable DNS replacement transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct DnsTransactionId([u8; 32]);

impl DnsTransactionId {
    #[allow(
        dead_code,
        reason = "the Linux DNS prepare seam consumes this minting API in the next U12 slice"
    )]
    pub(crate) fn new(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0; 32] {
            Err("DNS transaction identity must be non-zero")
        } else {
            Ok(Self(bytes))
        }
    }

    fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

/// Bounded single-token value returned by `resolvectl` for a DNS server or
/// routing/search domain. It cannot carry whitespace, control bytes, or argv.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(crate) struct PhysicalDnsValue(String);

impl PhysicalDnsValue {
    pub(crate) fn new(value: impl AsRef<str>) -> Result<Self, &'static str> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_PHYSICAL_DNS_VALUE_BYTES
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err("physical DNS value is invalid");
        }
        Ok(Self(value.to_string()))
    }

    #[allow(
        dead_code,
        reason = "the Linux DNS adapter consumes persisted values in the next U12 slice"
    )]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PhysicalDnsValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Exact pre-mutation state for one helper-derived tunnel interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub(crate) enum PhysicalDnsPrior {
    Resolved {
        servers: Vec<PhysicalDnsValue>,
        domains: Vec<PhysicalDnsValue>,
        default_route: Option<bool>,
    },
    Resolvconf {
        record: Option<Vec<u8>>,
    },
    MacOsResolverFiles,
}

#[derive(Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
enum PhysicalDnsPriorWire {
    Resolved {
        servers: BoundedVec<PhysicalDnsValue, MAX_RESOURCE_ITEMS>,
        domains: BoundedVec<PhysicalDnsValue, MAX_RESOURCE_ITEMS>,
        default_route: Option<bool>,
    },
    Resolvconf {
        record: Option<BoundedVec<u8, MAX_PHYSICAL_DNS_RECORD_BYTES>>,
    },
    MacOsResolverFiles,
}

impl<'de> Deserialize<'de> for PhysicalDnsPrior {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let prior = match PhysicalDnsPriorWire::deserialize(deserializer)? {
            PhysicalDnsPriorWire::Resolved {
                servers,
                domains,
                default_route,
            } => Self::Resolved {
                servers: servers.into_vec(),
                domains: domains.into_vec(),
                default_route,
            },
            PhysicalDnsPriorWire::Resolvconf { record } => Self::Resolvconf {
                record: record.map(BoundedVec::into_vec),
            },
            PhysicalDnsPriorWire::MacOsResolverFiles => Self::MacOsResolverFiles,
        };
        if !prior.is_valid() {
            return Err(serde::de::Error::custom("physical DNS prior is invalid"));
        }
        Ok(prior)
    }
}

impl PhysicalDnsPrior {
    fn is_valid(&self) -> bool {
        match self {
            Self::Resolved {
                servers, domains, ..
            } => {
                !has_duplicates(servers)
                    && !has_duplicates(domains)
                    && servers.len() <= MAX_RESOURCE_ITEMS
                    && domains.len() <= MAX_RESOURCE_ITEMS
            }
            Self::Resolvconf { record } => record.as_ref().is_none_or(|record| {
                record.len() <= MAX_PHYSICAL_DNS_RECORD_BYTES && std::str::from_utf8(record).is_ok()
            }),
            Self::MacOsResolverFiles => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhysicalDnsLink {
    tunnel: ResourceTag,
    prior: PhysicalDnsPrior,
}

impl PhysicalDnsLink {
    #[allow(
        dead_code,
        reason = "the Linux DNS prepare seam captures link priors in the next U12 slice"
    )]
    pub(crate) fn new(tunnel: ResourceTag, prior: PhysicalDnsPrior) -> Result<Self, &'static str> {
        if tunnel.kind() != ResourceKind::Tunnel {
            return Err("physical DNS link requires a tunnel resource");
        }
        Ok(Self { tunnel, prior })
    }

    pub(crate) const fn tunnel(&self) -> &ResourceTag {
        &self.tunnel
    }

    pub(crate) const fn prior(&self) -> &PhysicalDnsPrior {
        &self.prior
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PhysicalDnsStage {
    Prepared,
    EffectPendingObservation,
    ObservedOwned,
    ObservedAbsent,
    Superseded,
    OwnedReleasePending,
    AbsentReleasePending,
    SupersededReleasePending,
}

/// Durable binding between a logical DNS projection and the exact physical
/// backend plus captured prior link state needed for restart-safe rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HelperLedgerDns {
    resource: ResourceTag,
    backend: PhysicalDnsBackend,
    transaction_id: DnsTransactionId,
    intended_digest: PolicyDigest,
    stage: PhysicalDnsStage,
    links: Vec<PhysicalDnsLink>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerDnsWire {
    resource: ResourceTag,
    backend: PhysicalDnsBackend,
    transaction_id: DnsTransactionId,
    intended_digest: PolicyDigest,
    stage: PhysicalDnsStage,
    links: BoundedVec<PhysicalDnsLink, MAX_RESOURCE_ITEMS>,
}

impl<'de> Deserialize<'de> for HelperLedgerDns {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HelperLedgerDnsWire::deserialize(deserializer)?;
        let value = Self {
            resource: wire.resource,
            backend: wire.backend,
            transaction_id: wire.transaction_id,
            intended_digest: wire.intended_digest,
            stage: wire.stage,
            links: wire.links.into_vec(),
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[allow(
    dead_code,
    reason = "the Linux DNS executor consumes these crash transitions in the next U12 slice"
)]
impl HelperLedgerDns {
    #[allow(
        dead_code,
        reason = "the Linux DNS prepare seam persists physical ownership in the next U12 slice"
    )]
    pub(crate) fn prepared(
        resource: ResourceTag,
        backend: PhysicalDnsBackend,
        transaction_id: DnsTransactionId,
        intended_digest: PolicyDigest,
        links: Vec<PhysicalDnsLink>,
    ) -> Result<Self, &'static str> {
        let value = Self {
            resource,
            backend,
            transaction_id,
            intended_digest,
            stage: PhysicalDnsStage::Prepared,
            links,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.resource.kind() != ResourceKind::Dns
            || self.transaction_id.is_zero()
            || self.links.len() > MAX_RESOURCE_ITEMS
            || has_duplicates(self.links.iter().map(PhysicalDnsLink::tunnel))
            || self.links.iter().any(|link| {
                link.tunnel().generation() != self.resource.generation()
                    || !link.prior().is_valid()
                    || !matches!(
                        (self.backend, link.prior()),
                        (
                            PhysicalDnsBackend::LinuxResolved,
                            PhysicalDnsPrior::Resolved { .. }
                        ) | (
                            PhysicalDnsBackend::LinuxResolvconf,
                            PhysicalDnsPrior::Resolvconf { .. }
                        ) | (
                            PhysicalDnsBackend::MacOsResolverFiles,
                            PhysicalDnsPrior::MacOsResolverFiles
                        )
                    )
            })
        {
            return Err("physical DNS ownership is invalid");
        }
        Ok(())
    }

    pub(crate) const fn resource(&self) -> &ResourceTag {
        &self.resource
    }

    #[allow(
        dead_code,
        reason = "the Linux DNS recovery adapter consumes this in the next U12 slice"
    )]
    pub(crate) const fn backend(&self) -> PhysicalDnsBackend {
        self.backend
    }

    #[allow(
        dead_code,
        reason = "the Linux DNS recovery adapter consumes this in the next U12 slice"
    )]
    pub(crate) const fn transaction_id(&self) -> DnsTransactionId {
        self.transaction_id
    }

    const fn transaction_id_ref(&self) -> &DnsTransactionId {
        &self.transaction_id
    }

    pub(crate) const fn intended_digest(&self) -> PolicyDigest {
        self.intended_digest
    }

    pub(crate) const fn stage(&self) -> PhysicalDnsStage {
        self.stage
    }

    #[allow(
        dead_code,
        reason = "the Linux DNS recovery adapter consumes this in the next U12 slice"
    )]
    pub(crate) fn links(&self) -> &[PhysicalDnsLink] {
        &self.links
    }

    pub(crate) fn prepare_for(&self, projection: &PolicyProjection) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalDnsStage::ObservedOwned | PhysicalDnsStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("DNS projection does not match settled physical state");
        }
        Self::prepared(
            self.resource.clone(),
            self.backend,
            self.transaction_id,
            projection.digest(),
            self.links.clone(),
        )
    }

    pub(crate) fn mark_effect_pending(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalDnsStage::Prepared {
            return Err("DNS effect requires prepared ownership");
        }
        self.stage = PhysicalDnsStage::EffectPendingObservation;
        Ok(self)
    }

    pub(crate) fn confirm_observed(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if self.stage != PhysicalDnsStage::EffectPendingObservation
            || projection.policy() != &self.resource
            || projection.digest() != self.intended_digest
        {
            return Err("DNS observation requires a pending exact effect");
        }
        self.stage = settled_dns_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn mark_release_pending(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalDnsStage::ObservedOwned => PhysicalDnsStage::OwnedReleasePending,
            PhysicalDnsStage::ObservedAbsent => PhysicalDnsStage::AbsentReleasePending,
            PhysicalDnsStage::Superseded => PhysicalDnsStage::SupersededReleasePending,
            _ => return Err("DNS release requires settled ownership"),
        };
        Ok(self)
    }

    pub(crate) fn supersede(mut self) -> Result<Self, &'static str> {
        if self.stage != PhysicalDnsStage::ObservedOwned {
            return Err("only observed DNS ownership can be superseded");
        }
        self.stage = PhysicalDnsStage::Superseded;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_mutation(
        mut self,
        projection: &PolicyProjection,
    ) -> Result<Self, &'static str> {
        if !matches!(
            self.stage,
            PhysicalDnsStage::EffectPendingObservation
                | PhysicalDnsStage::ObservedOwned
                | PhysicalDnsStage::ObservedAbsent
        ) || projection.policy() != &self.resource
        {
            return Err("DNS rollback projection does not match physical state");
        }
        self.intended_digest = projection.digest();
        self.stage = settled_dns_stage(projection)?;
        Ok(self)
    }

    pub(crate) fn restore_after_failed_release(mut self) -> Result<Self, &'static str> {
        self.stage = match self.stage {
            PhysicalDnsStage::OwnedReleasePending => PhysicalDnsStage::ObservedOwned,
            PhysicalDnsStage::AbsentReleasePending => PhysicalDnsStage::ObservedAbsent,
            PhysicalDnsStage::SupersededReleasePending => PhysicalDnsStage::Superseded,
            _ => return Err("DNS release rollback requires pending release ownership"),
        };
        Ok(self)
    }
}

#[allow(
    dead_code,
    reason = "the Linux DNS executor confirms this state in the next U12 slice"
)]
fn settled_dns_stage(projection: &PolicyProjection) -> Result<PhysicalDnsStage, &'static str> {
    let PolicyProjection::Dns { assignments, .. } = projection else {
        return Err("physical DNS state requires a DNS projection");
    };
    if assignments
        .iter()
        .any(|assignment| !matches!(assignment.scope(), super::PrivilegedDnsScope::Suppressed))
    {
        Ok(PhysicalDnsStage::ObservedOwned)
    } else {
        Ok(PhysicalDnsStage::ObservedAbsent)
    }
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
    physical_firewalls: Vec<HelperLedgerFirewall>,
    physical_dns: Vec<HelperLedgerDns>,
    physical_routes: Vec<HelperLedgerRoutes>,
    released_resources: Vec<ResourceTag>,
    child_observations: Vec<ObservedChildIdentity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperLedgerWire {
    schema_version: u16,
    replay: ReplayRecord,
    resources: BoundedVec<HelperLedgerResource, MAX_RESOURCE_ITEMS>,
    policy_projections: BoundedVec<HelperLedgerPolicy, MAX_RESOURCE_ITEMS>,
    physical_firewalls: BoundedVec<HelperLedgerFirewall, MAX_RESOURCE_ITEMS>,
    #[serde(default)]
    physical_dns: BoundedVec<HelperLedgerDns, MAX_RESOURCE_ITEMS>,
    #[serde(default)]
    physical_routes: BoundedVec<HelperLedgerRoutes, MAX_RESOURCE_ITEMS>,
    released_resources: BoundedVec<ResourceTag, MAX_RESOURCE_ITEMS>,
    child_observations: BoundedVec<ObservedChildIdentity, MAX_RESOURCE_ITEMS>,
}

type HelperLedgerParts = (
    ReplayRecord,
    Vec<HelperLedgerResource>,
    Vec<HelperLedgerPolicy>,
    Vec<HelperLedgerFirewall>,
    Vec<HelperLedgerDns>,
    Vec<HelperLedgerRoutes>,
    Vec<ResourceTag>,
    Vec<ObservedChildIdentity>,
);

struct HelperLedgerInventory {
    resources: Vec<HelperLedgerResource>,
    policy_projections: Vec<HelperLedgerPolicy>,
    physical_firewalls: Vec<HelperLedgerFirewall>,
    physical_dns: Vec<HelperLedgerDns>,
    physical_routes: Vec<HelperLedgerRoutes>,
    released_resources: Vec<ResourceTag>,
    child_observations: Vec<ObservedChildIdentity>,
}

pub(crate) struct HelperLedgerPhysicalOwnership {
    pub(crate) firewalls: Vec<HelperLedgerFirewall>,
    pub(crate) dns: Vec<HelperLedgerDns>,
    pub(crate) routes: Vec<HelperLedgerRoutes>,
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
            HelperLedgerInventory {
                resources: wire.resources.into_vec(),
                policy_projections: wire.policy_projections.into_vec(),
                physical_firewalls: wire.physical_firewalls.into_vec(),
                physical_dns: wire.physical_dns.into_vec(),
                physical_routes: wire.physical_routes.into_vec(),
                released_resources: wire.released_resources.into_vec(),
                child_observations: wire.child_observations.into_vec(),
            },
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
            physical_firewalls: Vec::new(),
            physical_dns: Vec::new(),
            physical_routes: Vec::new(),
            released_resources: Vec::new(),
            child_observations: Vec::new(),
        }
    }

    pub(crate) fn next_helper_session(
        &self,
    ) -> Result<(HelperEpoch, RequestSequence), OperationError> {
        self.replay.next_helper_session()
    }

    #[cfg(test)]
    pub(crate) fn new(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_policies(replay, resources, Vec::new(), child_observations)
    }

    #[cfg(test)]
    pub(crate) fn new_with_policies(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_physical_firewalls(
            replay,
            resources,
            policy_projections,
            Vec::new(),
            child_observations,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_physical_firewalls(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        physical_firewalls: Vec<HelperLedgerFirewall>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_schema(
            HELPER_LEDGER_SCHEMA_VERSION,
            replay,
            HelperLedgerInventory {
                resources,
                policy_projections,
                physical_firewalls,
                physical_dns: Vec::new(),
                physical_routes: Vec::new(),
                released_resources: Vec::new(),
                child_observations,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_physical_ownership(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        physical_firewalls: Vec<HelperLedgerFirewall>,
        physical_dns: Vec<HelperLedgerDns>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_physical_ownership_and_released(
            replay,
            resources,
            policy_projections,
            physical_firewalls,
            physical_dns,
            Vec::new(),
            child_observations,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_physical_routes(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        physical_routes: Vec<HelperLedgerRoutes>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_complete_physical_ownership_and_released(
            replay,
            resources,
            policy_projections,
            HelperLedgerPhysicalOwnership {
                firewalls: Vec::new(),
                dns: Vec::new(),
                routes: physical_routes,
            },
            Vec::new(),
            child_observations,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_physical_ownership_and_released(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        physical_firewalls: Vec<HelperLedgerFirewall>,
        physical_dns: Vec<HelperLedgerDns>,
        released_resources: Vec<ResourceTag>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_complete_physical_ownership_and_released(
            replay,
            resources,
            policy_projections,
            HelperLedgerPhysicalOwnership {
                firewalls: physical_firewalls,
                dns: physical_dns,
                routes: Vec::new(),
            },
            released_resources,
            child_observations,
        )
    }

    pub(crate) fn new_with_complete_physical_ownership_and_released(
        replay: ReplayRecord,
        resources: Vec<HelperLedgerResource>,
        policy_projections: Vec<HelperLedgerPolicy>,
        physical: HelperLedgerPhysicalOwnership,
        released_resources: Vec<ResourceTag>,
        child_observations: Vec<ObservedChildIdentity>,
    ) -> Result<Self, &'static str> {
        Self::new_with_schema(
            HELPER_LEDGER_SCHEMA_VERSION,
            replay,
            HelperLedgerInventory {
                resources,
                policy_projections,
                physical_firewalls: physical.firewalls,
                physical_dns: physical.dns,
                physical_routes: physical.routes,
                released_resources,
                child_observations,
            },
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one constructor validates the entire authenticated ledger as one invariant"
    )]
    fn new_with_schema(
        schema_version: u16,
        replay: ReplayRecord,
        inventory: HelperLedgerInventory,
    ) -> Result<Self, &'static str> {
        let HelperLedgerInventory {
            resources,
            policy_projections,
            physical_firewalls,
            physical_dns,
            physical_routes,
            released_resources,
            child_observations,
        } = inventory;
        if schema_version != HELPER_LEDGER_SCHEMA_VERSION
            || resources.len() > MAX_RESOURCE_ITEMS
            || policy_projections.len() > MAX_RESOURCE_ITEMS
            || physical_firewalls.len() > MAX_RESOURCE_ITEMS
            || physical_dns.len() > MAX_RESOURCE_ITEMS
            || physical_routes.len() > MAX_RESOURCE_ITEMS
            || released_resources.len() > MAX_RESOURCE_ITEMS
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
                physical_firewalls
                    .iter()
                    .map(HelperLedgerFirewall::resource),
            )
            || has_duplicates(
                physical_firewalls
                    .iter()
                    .map(HelperLedgerFirewall::transaction_id_ref),
            )
            || physical_firewalls.iter().any(|physical| {
                physical.transaction_id().is_zero()
                    || physical.resource().kind() != ResourceKind::Firewall
                    || physical.resource().authority_epoch() != Some(replay.authority_epoch())
                    || !physical_matches_logical(physical, &resources, &policy_projections)
            })
            || physical_inventory_is_ambiguous(&physical_firewalls)
            || policy_projections.iter().any(|policy| {
                policy.resource().kind() == ResourceKind::Firewall
                    && !physical_firewalls
                        .iter()
                        .any(|physical| physical.resource() == policy.resource())
            })
            || has_duplicates(physical_dns.iter().map(HelperLedgerDns::resource))
            || has_duplicates(physical_dns.iter().map(HelperLedgerDns::transaction_id_ref))
            || physical_dns.iter().any(|physical| {
                physical.validate().is_err()
                    || physical.resource().authority_epoch() != Some(replay.authority_epoch())
                    || !physical_dns_matches_logical(physical, &resources, &policy_projections)
            })
            || physical_dns_inventory_is_ambiguous(&physical_dns)
            || has_duplicates(physical_routes.iter().map(HelperLedgerRoutes::resource))
            || has_duplicates(
                physical_routes
                    .iter()
                    .map(HelperLedgerRoutes::transaction_id_ref),
            )
            || physical_routes.iter().any(|physical| {
                physical.transaction_id().is_zero()
                    || physical.validate().is_err()
                    || physical.resource().authority_epoch() != Some(replay.authority_epoch())
                    || !physical_routes_match_logical(physical, &resources, &policy_projections)
            })
            || physical_routes_inventory_is_ambiguous(&physical_routes)
            || released_resources_are_invalid(&released_resources, &resources)
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
        let record = Self {
            schema_version,
            replay,
            resources,
            policy_projections,
            physical_firewalls,
            physical_dns,
            physical_routes,
            released_resources,
            child_observations,
        };
        let mut writer = BoundedLedgerWriter::default();
        serde_json::to_writer(&mut writer, &record)
            .map_err(|_| "helper ownership ledger exceeds its durable capacity")?;
        Ok(record)
    }

    #[cfg(test)]
    pub(crate) fn resources(&self) -> &[HelperLedgerResource] {
        &self.resources
    }

    pub(crate) fn into_parts(self) -> HelperLedgerParts {
        (
            self.replay,
            self.resources,
            self.policy_projections,
            self.physical_firewalls,
            self.physical_dns,
            self.physical_routes,
            self.released_resources,
            self.child_observations,
        )
    }

    #[cfg(test)]
    pub(crate) fn physical_firewalls(&self) -> &[HelperLedgerFirewall] {
        &self.physical_firewalls
    }

    #[cfg(test)]
    pub(crate) fn physical_dns(&self) -> &[HelperLedgerDns] {
        &self.physical_dns
    }

    #[cfg(test)]
    pub(crate) fn physical_routes(&self) -> &[HelperLedgerRoutes] {
        &self.physical_routes
    }

    #[cfg(test)]
    pub(crate) fn released_resources(&self) -> &[ResourceTag] {
        &self.released_resources
    }
}

fn released_resources_are_invalid(
    released: &[ResourceTag],
    active: &[HelperLedgerResource],
) -> bool {
    let active_resources = active
        .iter()
        .map(HelperLedgerResource::resource)
        .collect::<std::collections::BTreeSet<_>>();
    released_identity_set_is_invalid(released)
        || released
            .iter()
            .any(|resource| active_resources.contains(resource))
}

fn physical_routes_match_logical(
    physical: &HelperLedgerRoutes,
    resources: &[HelperLedgerResource],
    policies: &[HelperLedgerPolicy],
) -> bool {
    let Some(resource) = resources
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    let Some(policy) = policies
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    let projection = match physical.stage() {
        PhysicalRouteStage::Prepared | PhysicalRouteStage::EffectPendingObservation => {
            if resource.state() != HelperResourceState::PendingEffect
                || physical.intended_digest() != policy.intended().digest()
            {
                return false;
            }
            policy.intended()
        }
        PhysicalRouteStage::ObservedOwned
        | PhysicalRouteStage::ObservedAbsent
        | PhysicalRouteStage::Superseded => {
            if resource.state() != HelperResourceState::Owned {
                return false;
            }
            let Some(effective) = policy.effective() else {
                return false;
            };
            if physical.intended_digest() != effective.digest() {
                return false;
            }
            effective
        }
        PhysicalRouteStage::OwnedReleasePending
        | PhysicalRouteStage::AbsentReleasePending
        | PhysicalRouteStage::SupersededReleasePending => {
            if resource.state() != HelperResourceState::PendingRelease {
                return false;
            }
            let Some(effective) = policy.effective() else {
                return false;
            };
            if physical.intended_digest() != effective.digest() {
                return false;
            }
            effective
        }
    };
    let Some(recorded_is_empty) = physical_route_payload_matches(physical, projection) else {
        return false;
    };
    matches!(
        (recorded_is_empty, physical.stage()),
        (
            false,
            PhysicalRouteStage::Prepared
                | PhysicalRouteStage::EffectPendingObservation
                | PhysicalRouteStage::ObservedOwned
                | PhysicalRouteStage::Superseded
                | PhysicalRouteStage::OwnedReleasePending
                | PhysicalRouteStage::SupersededReleasePending
        ) | (
            true,
            PhysicalRouteStage::Prepared
                | PhysicalRouteStage::EffectPendingObservation
                | PhysicalRouteStage::ObservedAbsent
                | PhysicalRouteStage::AbsentReleasePending
        )
    )
}

fn physical_route_payload_matches(
    physical: &HelperLedgerRoutes,
    projection: &PolicyProjection,
) -> Option<bool> {
    let PolicyProjection::Routes {
        routes,
        redirects,
        tunnels,
        ..
    } = projection
    else {
        return None;
    };
    let mut expected = routes
        .iter()
        .map(super::ScopedRoute::destination)
        .collect::<std::collections::HashSet<_>>();
    if expected.len() != routes.len() {
        return None;
    }
    for redirect in redirects {
        for destination in redirect.destinations().ok()? {
            if !expected.insert(destination) {
                return None;
            }
        }
    }
    let recorded = physical
        .entries()
        .iter()
        .map(PhysicalRouteEntry::destination)
        .collect::<std::collections::HashSet<_>>();
    let expected_bypass = if expected.is_empty() {
        std::collections::HashSet::new()
    } else {
        tunnels
            .iter()
            .flat_map(super::PrivilegedFirewallTunnel::endpoint_ips)
            .copied()
            .collect::<std::collections::HashSet<_>>()
    };
    let recorded_bypass = physical
        .transport_bypass_targets()
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    if expected != recorded
        || expected_bypass.len() != physical.transport_bypass_targets().len()
        || expected_bypass != recorded_bypass
    {
        return None;
    }
    Some(recorded.is_empty())
}

fn physical_routes_inventory_is_ambiguous(records: &[HelperLedgerRoutes]) -> bool {
    let current_owners = records
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalRouteStage::ObservedOwned | PhysicalRouteStage::OwnedReleasePending
            )
        })
        .count();
    let pending_replacements = records
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalRouteStage::Prepared | PhysicalRouteStage::EffectPendingObservation
            )
        })
        .count();
    let backend = records.first().map(HelperLedgerRoutes::backend);
    current_owners > 1
        || pending_replacements > 1
        || records
            .iter()
            .any(|physical| Some(physical.backend()) != backend)
}

pub(crate) fn released_identity_set_is_invalid(released: &[ResourceTag]) -> bool {
    let released_resources = released.iter().collect::<std::collections::BTreeSet<_>>();
    let mut identities = std::collections::BTreeSet::new();
    if released.iter().any(|resource| {
        let Some(profile) = resource.profile_id() else {
            return true;
        };
        !resource.is_tunnel_scoped() || !identities.insert((profile, resource.kind()))
    }) {
        return true;
    }
    released.iter().any(|resource| {
        resource.kind() == ResourceKind::ProcessGroup
            && resource
                .corresponding_tunnel()
                .is_none_or(|tunnel| !released_resources.contains(&tunnel))
    })
}

fn physical_dns_matches_logical(
    physical: &HelperLedgerDns,
    resources: &[HelperLedgerResource],
    policies: &[HelperLedgerPolicy],
) -> bool {
    let Some(resource) = resources
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    let Some(policy) = policies
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    let PolicyProjection::Dns { assignments, .. } = policy.intended() else {
        return false;
    };
    let expected_links = assignments
        .iter()
        .filter(|assignment| !matches!(assignment.scope(), super::PrivilegedDnsScope::Suppressed))
        .map(super::PrivilegedDnsAssignment::tunnel)
        .collect::<std::collections::BTreeSet<_>>();
    let recorded_links = physical
        .links()
        .iter()
        .map(PhysicalDnsLink::tunnel)
        .collect::<std::collections::BTreeSet<_>>();
    if physical.backend() == PhysicalDnsBackend::MacOsResolverFiles {
        if !recorded_links.is_empty() {
            return false;
        }
    } else if recorded_links != expected_links {
        return false;
    }
    match physical.stage() {
        PhysicalDnsStage::Prepared | PhysicalDnsStage::EffectPendingObservation => {
            resource.state() == HelperResourceState::PendingEffect
                && physical.intended_digest() == policy.intended().digest()
        }
        stage @ (PhysicalDnsStage::ObservedOwned
        | PhysicalDnsStage::ObservedAbsent
        | PhysicalDnsStage::Superseded) => {
            resource.state() == HelperResourceState::Owned
                && policy
                    .effective()
                    .is_some_and(|effective| physical.intended_digest() == effective.digest())
                && dns_stage_matches_projection(stage, policy.effective())
        }
        stage @ (PhysicalDnsStage::OwnedReleasePending
        | PhysicalDnsStage::AbsentReleasePending
        | PhysicalDnsStage::SupersededReleasePending) => {
            resource.state() == HelperResourceState::PendingRelease
                && policy
                    .effective()
                    .is_some_and(|effective| physical.intended_digest() == effective.digest())
                && dns_stage_matches_projection(stage, policy.effective())
        }
    }
}

fn dns_stage_matches_projection(
    stage: PhysicalDnsStage,
    projection: Option<&PolicyProjection>,
) -> bool {
    let Some(PolicyProjection::Dns { assignments, .. }) = projection else {
        return false;
    };
    let active = assignments
        .iter()
        .any(|assignment| !matches!(assignment.scope(), super::PrivilegedDnsScope::Suppressed));
    matches!(
        (active, stage),
        (
            true,
            PhysicalDnsStage::ObservedOwned
                | PhysicalDnsStage::Superseded
                | PhysicalDnsStage::OwnedReleasePending
                | PhysicalDnsStage::SupersededReleasePending
        ) | (
            false,
            PhysicalDnsStage::ObservedAbsent | PhysicalDnsStage::AbsentReleasePending
        )
    )
}

fn physical_dns_inventory_is_ambiguous(records: &[HelperLedgerDns]) -> bool {
    let current_owners = records
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalDnsStage::ObservedOwned | PhysicalDnsStage::OwnedReleasePending
            )
        })
        .count();
    let pending_replacements = records
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalDnsStage::Prepared | PhysicalDnsStage::EffectPendingObservation
            )
        })
        .count();
    let backend = records.first().map(HelperLedgerDns::backend);
    current_owners > 1
        || pending_replacements > 1
        || records
            .iter()
            .any(|physical| Some(physical.backend()) != backend)
}

fn physical_inventory_is_ambiguous(firewalls: &[HelperLedgerFirewall]) -> bool {
    let current_owners = firewalls
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalFirewallStage::ObservedOwned | PhysicalFirewallStage::OwnedReleasePending
            )
        })
        .count();
    let pending_replacements = firewalls
        .iter()
        .filter(|physical| {
            matches!(
                physical.stage(),
                PhysicalFirewallStage::Prepared | PhysicalFirewallStage::EffectPendingObservation
            )
        })
        .count();
    current_owners > 1 || pending_replacements > 1
}

fn physical_matches_logical(
    physical: &HelperLedgerFirewall,
    resources: &[HelperLedgerResource],
    policies: &[HelperLedgerPolicy],
) -> bool {
    let Some(resource) = resources
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    let Some(policy) = policies
        .iter()
        .find(|entry| entry.resource() == physical.resource())
    else {
        return false;
    };
    match physical.stage() {
        PhysicalFirewallStage::Prepared | PhysicalFirewallStage::EffectPendingObservation => {
            resource.state() == HelperResourceState::PendingEffect
                && physical.intended_digest() == policy.intended().digest()
        }
        PhysicalFirewallStage::ObservedOwned
        | PhysicalFirewallStage::ObservedAbsent
        | PhysicalFirewallStage::Superseded => {
            resource.state() == HelperResourceState::Owned
                && policy
                    .effective()
                    .is_some_and(|effective| physical.intended_digest() == effective.digest())
        }
        PhysicalFirewallStage::OwnedReleasePending
        | PhysicalFirewallStage::AbsentReleasePending
        | PhysicalFirewallStage::SupersededReleasePending => {
            resource.state() == HelperResourceState::PendingRelease
                && policy
                    .effective()
                    .is_some_and(|effective| physical.intended_digest() == effective.digest())
        }
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
        tunnel_at(7)
    }

    fn tunnel_at(generation: u64) -> ResourceTag {
        ResourceTag::tunnel(
            crate::vortix_core::profile::ProfileId::parse(
                "a".repeat(crate::vortix_core::profile::ProfileId::HEX_LEN),
            )
            .unwrap(),
            generation,
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
    fn released_tunnel_inventory_is_closed_bounded_and_not_live_ownership() {
        let replay = || {
            serde_json::from_value::<ReplayRecord>(serde_json::json!({
                "state": "unused",
                "record": {
                    "schema_version": crate::vortix_core::privileged::CONTRACT_SCHEMA_VERSION,
                    "authority_epoch": 3,
                    "lease_id": vec![5; 32],
                    "principal_binding": vec![7; 32],
                    "initial_helper_epoch": 8
                }
            }))
            .unwrap()
        };
        let tunnel = tunnel();
        let group = ResourceTag::profile(
            tunnel.profile_id().unwrap().clone(),
            tunnel.generation(),
            ResourceKind::ProcessGroup,
        )
        .unwrap();
        let record = HelperLedgerRecord::new_with_physical_ownership_and_released(
            replay(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![tunnel.clone(), group.clone()],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            record.released_resources(),
            &[tunnel.clone(), group.clone()]
        );
        assert!(
            HelperLedgerRecord::new_with_physical_ownership_and_released(
                replay(),
                vec![HelperLedgerResource::owned(tunnel.clone())],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![tunnel.clone()],
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            HelperLedgerRecord::new_with_physical_ownership_and_released(
                replay(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![group],
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            HelperLedgerRecord::new_with_physical_ownership_and_released(
                replay(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                vec![tunnel, tunnel_at(8)],
                Vec::new(),
            )
            .is_err()
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

        let physical = HelperLedgerFirewall::prepared(
            resource.clone(),
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        );
        let record = HelperLedgerRecord::new_with_physical_firewalls(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
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
        let physical = HelperLedgerFirewall::prepared(
            resource.clone(),
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        );
        let record = HelperLedgerRecord::new_with_physical_firewalls(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
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

    #[test]
    fn firewall_projection_requires_exact_prepared_physical_ownership() {
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
        let physical = HelperLedgerFirewall::prepared(
            resource.clone(),
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        );

        let record = HelperLedgerRecord::new_with_physical_firewalls(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
            Vec::new(),
        )
        .unwrap();

        let mut missing = serde_json::to_value(&record).unwrap();
        missing["physical_firewalls"] = serde_json::json!([]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(missing).is_err());
    }

    #[test]
    fn physical_route_plan_is_bounded_and_bound_to_the_exact_projection() {
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
            ResourceKind::Routes,
        )
        .unwrap();
        let tunnel = tunnel();
        let route =
            super::super::ScopedRoute::new("10.0.0.0/8".parse().unwrap(), tunnel.clone()).unwrap();
        let subject = super::super::PrivilegedFirewallTunnel::new(
            tunnel,
            vec!["198.51.100.1".parse().unwrap()],
            vec!["10.0.0.0/8".parse().unwrap()],
            super::super::PrivilegedFirewallRole::Primary,
        )
        .unwrap();
        let projection = PolicyProjection::Routes {
            policy: resource.clone(),
            routes: vec![route],
            redirects: Vec::new(),
            tunnels: vec![subject],
        };
        let physical = HelperLedgerRoutes::prepared(
            resource.clone(),
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([11; 32]).unwrap(),
            projection.digest(),
            vec![PhysicalRouteEntry::new(
                "10.0.0.0/8".parse().unwrap(),
                "vxroute0".into(),
                Some("10.0.0.1".parse().unwrap()),
                Some(20),
            )
            .unwrap()],
            vec!["198.51.100.1".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        let record = HelperLedgerRecord::new_with_physical_routes(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
            Vec::new(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&record).unwrap();
        let decoded: HelperLedgerRecord = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.physical_routes().len(), 1);
        assert_eq!(
            decoded.physical_routes()[0].transport_bypass_targets(),
            &["198.51.100.1".parse::<IpAddr>().unwrap()]
        );

        let mut wrong_digest = encoded.clone();
        wrong_digest["physical_routes"][0]["intended_digest"] = serde_json::json!(vec![9; 32]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(wrong_digest).is_err());

        let mut duplicate_destination = encoded.clone();
        let duplicate = duplicate_destination["physical_routes"][0]["entries"][0].clone();
        duplicate_destination["physical_routes"][0]["entries"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(serde_json::from_value::<HelperLedgerRecord>(duplicate_destination).is_err());

        let mut duplicate_bypass = encoded.clone();
        let duplicate =
            duplicate_bypass["physical_routes"][0]["transport_bypass_targets"][0].clone();
        duplicate_bypass["physical_routes"][0]["transport_bypass_targets"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(serde_json::from_value::<HelperLedgerRecord>(duplicate_bypass).is_err());

        let mut wrong_bypass = encoded;
        wrong_bypass["physical_routes"][0]["transport_bypass_targets"] =
            serde_json::json!(["203.0.113.9"]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(wrong_bypass).is_err());
    }

    #[test]
    fn physical_route_ownership_rejects_legacy_protocol_route_domains() {
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            1,
            ResourceKind::Routes,
        )
        .unwrap();
        let destination = "10.0.0.0/8".parse().unwrap();
        let entry = PhysicalRouteEntry::new(destination, "vxroute0".into(), None, None).unwrap();
        let intended = PolicyProjection::Routes {
            policy: resource.clone(),
            routes: vec![super::super::ScopedRoute::new(destination, tunnel()).unwrap()],
            redirects: Vec::new(),
            tunnels: vec![super::super::PrivilegedFirewallTunnel::new(
                tunnel(),
                vec!["198.51.100.1".parse().unwrap()],
                vec![destination],
                super::super::PrivilegedFirewallRole::Primary,
            )
            .unwrap()],
        };
        assert!(HelperLedgerRoutes::prepared(
            resource.clone(),
            PhysicalRouteBackend::LinuxIpMain,
            RouteTransactionId::new([11; 32]).unwrap(),
            intended.digest(),
            vec![entry.clone()],
            Vec::new(),
            Vec::new(),
        )
        .is_err());
        assert!(HelperLedgerRoutes::prepared(
            resource,
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([12; 32]).unwrap(),
            intended.digest(),
            vec![entry],
            vec!["198.51.100.1".parse().unwrap()],
            Vec::new(),
        )
        .is_ok());
    }

    #[test]
    fn macos_route_ownership_binds_every_endpoint_to_one_exact_host_route() {
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            1,
            ResourceKind::Routes,
        )
        .unwrap();
        let endpoint = "198.51.100.1".parse::<IpAddr>().unwrap();
        let bypass = PhysicalRouteEntry::new(
            "198.51.100.1/32".parse().unwrap(),
            "en0".into(),
            Some("192.0.2.1".parse().unwrap()),
            None,
        )
        .unwrap();
        assert!(HelperLedgerRoutes::prepared(
            resource.clone(),
            PhysicalRouteBackend::MacOsScopedV1,
            RouteTransactionId::new([13; 32]).unwrap(),
            PolicyDigest::for_test(super::super::OperationDigest::of_bytes(b"macos-route-plan")),
            Vec::new(),
            vec![endpoint],
            vec![bypass.clone()],
        )
        .is_ok());
        assert!(HelperLedgerRoutes::prepared(
            resource.clone(),
            PhysicalRouteBackend::MacOsScopedV1,
            RouteTransactionId::new([14; 32]).unwrap(),
            PolicyDigest::for_test(super::super::OperationDigest::of_bytes(
                b"missing-bypass-route",
            )),
            Vec::new(),
            vec![endpoint],
            Vec::new(),
        )
        .is_err());
        assert!(HelperLedgerRoutes::prepared(
            resource,
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([15; 32]).unwrap(),
            PolicyDigest::for_test(super::super::OperationDigest::of_bytes(
                b"linux-cannot-carry-macos-route",
            )),
            Vec::new(),
            vec![endpoint],
            vec![bypass],
        )
        .is_err());
    }

    #[test]
    fn physical_route_inventory_cannot_exceed_the_durable_ledger_budget() {
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
            ResourceKind::Routes,
        )
        .unwrap();
        let tunnel = tunnel();
        let destinations = (0_u16..256)
            .map(|index| {
                format!("10.0.{}.0/24", u8::try_from(index).unwrap())
                    .parse::<Cidr>()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let routes = destinations
            .iter()
            .map(|destination| {
                super::super::ScopedRoute::new(*destination, tunnel.clone()).unwrap()
            })
            .collect::<Vec<_>>();
        let subject = super::super::PrivilegedFirewallTunnel::new(
            tunnel,
            vec!["198.51.100.1".parse().unwrap()],
            destinations.clone(),
            super::super::PrivilegedFirewallRole::Primary,
        )
        .unwrap();
        let projection = PolicyProjection::Routes {
            policy: resource.clone(),
            routes,
            redirects: Vec::new(),
            tunnels: vec![subject],
        };
        let entries = destinations
            .into_iter()
            .map(|destination| {
                PhysicalRouteEntry::new(destination, "vxroute0".into(), None, None).unwrap()
            })
            .collect();
        let physical = HelperLedgerRoutes::prepared(
            resource.clone(),
            PhysicalRouteBackend::LinuxPolicyV1,
            RouteTransactionId::new([11; 32]).unwrap(),
            projection.digest(),
            entries,
            vec!["198.51.100.1".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();

        assert!(HelperLedgerRecord::new_with_physical_routes(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn physical_dns_prior_is_bounded_and_bound_to_the_exact_projection() {
        let empty_resolvconf: PhysicalDnsPrior = serde_json::from_value(serde_json::json!({
            "backend": "resolvconf",
            "record": []
        }))
        .unwrap();
        assert_eq!(
            empty_resolvconf,
            PhysicalDnsPrior::Resolvconf {
                record: Some(Vec::new())
            }
        );

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
            7,
            ResourceKind::Dns,
        )
        .unwrap();
        let assignment = super::super::PrivilegedDnsAssignment::new(
            tunnel(),
            vec!["1.1.1.1".parse().unwrap()],
            vec![super::super::DnsHostname::new("corp.example").unwrap()],
            super::super::PrivilegedDnsScope::CatchAll,
        )
        .unwrap();
        let projection = PolicyProjection::Dns {
            policy: resource.clone(),
            assignments: vec![assignment],
        };
        let prior = PhysicalDnsPrior::Resolved {
            servers: vec![PhysicalDnsValue::new("9.9.9.9").unwrap()],
            domains: vec![PhysicalDnsValue::new("~legacy.example").unwrap()],
            default_route: Some(false),
        };
        let physical = HelperLedgerDns::prepared(
            resource.clone(),
            PhysicalDnsBackend::LinuxResolved,
            DnsTransactionId::new([4; 32]).unwrap(),
            projection.digest(),
            vec![PhysicalDnsLink::new(tunnel(), prior).unwrap()],
        )
        .unwrap();
        let record = HelperLedgerRecord::new_with_physical_ownership(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            Vec::new(),
            vec![physical],
            Vec::new(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&record).unwrap();
        let decoded: HelperLedgerRecord = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.physical_dns().len(), 1);
        assert_eq!(decoded.physical_dns()[0].links().len(), 1);
        assert_eq!(
            decoded.physical_dns()[0].links()[0].prior().clone(),
            PhysicalDnsPrior::Resolved {
                servers: vec![PhysicalDnsValue::new("9.9.9.9").unwrap()],
                domains: vec![PhysicalDnsValue::new("~legacy.example").unwrap()],
                default_route: Some(false),
            }
        );

        let non_utf8_resolvconf = serde_json::json!({
            "backend": "resolvconf",
            "record": [255]
        });
        assert!(serde_json::from_value::<PhysicalDnsPrior>(non_utf8_resolvconf).is_err());

        let mut missing_link = encoded;
        missing_link["physical_dns"][0]["links"] = serde_json::json!([]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(missing_link).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture proves generation-bound rollback and owner cardinality together"
    )]
    fn physical_dns_replacement_binds_each_generation_prior_and_has_one_owner() {
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
        let prior = PhysicalDnsPrior::Resolved {
            servers: vec![PhysicalDnsValue::new("9.9.9.9").unwrap()],
            domains: vec![PhysicalDnsValue::new("~legacy.example").unwrap()],
            default_route: Some(false),
        };
        let old_resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            7,
            ResourceKind::Dns,
        )
        .unwrap();
        let old_projection = PolicyProjection::Dns {
            policy: old_resource.clone(),
            assignments: vec![super::super::PrivilegedDnsAssignment::new(
                tunnel_at(7),
                vec!["1.1.1.1".parse().unwrap()],
                vec![super::super::DnsHostname::new("corp.example").unwrap()],
                super::super::PrivilegedDnsScope::CatchAll,
            )
            .unwrap()],
        };
        let old_physical = HelperLedgerDns::prepared(
            old_resource.clone(),
            PhysicalDnsBackend::LinuxResolved,
            DnsTransactionId::new([4; 32]).unwrap(),
            old_projection.digest(),
            vec![PhysicalDnsLink::new(tunnel_at(7), prior.clone()).unwrap()],
        )
        .unwrap()
        .mark_effect_pending()
        .unwrap()
        .confirm_observed(&old_projection)
        .unwrap()
        .supersede()
        .unwrap();
        assert_eq!(
            old_physical
                .clone()
                .mark_release_pending()
                .unwrap()
                .restore_after_failed_release()
                .unwrap()
                .stage(),
            PhysicalDnsStage::Superseded
        );
        let new_resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            8,
            ResourceKind::Dns,
        )
        .unwrap();
        let new_projection = PolicyProjection::Dns {
            policy: new_resource.clone(),
            assignments: vec![super::super::PrivilegedDnsAssignment::new(
                tunnel_at(8),
                vec!["1.1.1.1".parse().unwrap()],
                vec![super::super::DnsHostname::new("corp.example").unwrap()],
                super::super::PrivilegedDnsScope::CatchAll,
            )
            .unwrap()],
        };
        let new_physical = HelperLedgerDns::prepared(
            new_resource.clone(),
            PhysicalDnsBackend::LinuxResolved,
            DnsTransactionId::new([6; 32]).unwrap(),
            new_projection.digest(),
            vec![PhysicalDnsLink::new(tunnel_at(8), prior).unwrap()],
        )
        .unwrap();
        let new_observed = new_physical
            .clone()
            .mark_effect_pending()
            .unwrap()
            .confirm_observed(&new_projection)
            .unwrap();
        assert_eq!(
            new_observed
                .clone()
                .mark_release_pending()
                .unwrap()
                .restore_after_failed_release()
                .unwrap()
                .stage(),
            PhysicalDnsStage::ObservedOwned
        );
        assert_eq!(
            new_observed
                .restore_after_failed_mutation(&new_projection)
                .unwrap()
                .stage(),
            PhysicalDnsStage::ObservedOwned
        );
        let record = HelperLedgerRecord::new_with_physical_ownership(
            replay,
            vec![
                HelperLedgerResource::owned(old_resource.clone()),
                HelperLedgerResource::pending(new_resource.clone()),
            ],
            vec![
                HelperLedgerPolicy::new(old_resource, old_projection.clone(), Some(old_projection))
                    .unwrap(),
                HelperLedgerPolicy::new(new_resource, new_projection, None).unwrap(),
            ],
            Vec::new(),
            vec![old_physical, new_physical],
            Vec::new(),
        )
        .unwrap();

        let mut independent_prior = serde_json::to_value(&record).unwrap();
        independent_prior["physical_dns"][1]["links"][0]["prior"]["servers"] =
            serde_json::json!(["8.8.8.8"]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(independent_prior).is_ok());

        let mut false_absence = serde_json::to_value(&record).unwrap();
        false_absence["physical_dns"][0]["stage"] = serde_json::json!("observed_absent");
        assert!(serde_json::from_value::<HelperLedgerRecord>(false_absence).is_err());

        let mut second_owner = serde_json::to_value(record).unwrap();
        second_owner["physical_dns"][0]["stage"] = serde_json::json!("observed_owned");
        second_owner["physical_dns"][1]["stage"] = serde_json::json!("observed_owned");
        second_owner["resources"][1]["state"] = serde_json::json!("owned");
        let intended = second_owner["policy_projections"][1]["intended"].clone();
        second_owner["policy_projections"][1]["effective"] = intended;
        assert!(serde_json::from_value::<HelperLedgerRecord>(second_owner).is_err());
    }

    #[test]
    fn physical_dns_backend_cannot_change_while_prior_ownership_remains() {
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            7,
            ResourceKind::Dns,
        )
        .unwrap();
        let projection = PolicyProjection::Dns {
            policy: resource.clone(),
            assignments: vec![super::super::PrivilegedDnsAssignment::new(
                tunnel_at(7),
                vec!["1.1.1.1".parse().unwrap()],
                vec![super::super::DnsHostname::new("corp.example").unwrap()],
                super::super::PrivilegedDnsScope::CatchAll,
            )
            .unwrap()],
        };
        let first = HelperLedgerDns::prepared(
            resource,
            PhysicalDnsBackend::LinuxResolved,
            DnsTransactionId::new([4; 32]).unwrap(),
            projection.digest(),
            vec![PhysicalDnsLink::new(
                tunnel_at(7),
                PhysicalDnsPrior::Resolved {
                    servers: Vec::new(),
                    domains: Vec::new(),
                    default_route: None,
                },
            )
            .unwrap()],
        )
        .unwrap();
        let second_resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            8,
            ResourceKind::Dns,
        )
        .unwrap();
        let second = HelperLedgerDns::prepared(
            second_resource,
            PhysicalDnsBackend::LinuxResolvconf,
            DnsTransactionId::new([6; 32]).unwrap(),
            projection.digest(),
            vec![
                PhysicalDnsLink::new(tunnel_at(8), PhysicalDnsPrior::Resolvconf { record: None })
                    .unwrap(),
            ],
        )
        .unwrap();
        assert!(physical_dns_inventory_is_ambiguous(&[first, second]));
    }

    #[test]
    fn superseded_release_rollback_cannot_mint_current_firewall_ownership() {
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
        let observed = HelperLedgerFirewall::prepared(
            resource,
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        )
        .mark_effect_pending()
        .unwrap()
        .confirm_observed(&projection)
        .unwrap();
        let superseded = observed.supersede().unwrap();
        let pending = superseded.mark_release_pending().unwrap();
        assert_eq!(
            pending.stage(),
            PhysicalFirewallStage::SupersededReleasePending
        );
        assert_eq!(
            pending.restore_after_failed_release().unwrap().stage(),
            PhysicalFirewallStage::Superseded
        );
    }

    #[test]
    fn absent_release_rollback_cannot_mint_firewall_ownership() {
        let resource = ResourceTag::topology(
            crate::vortix_core::control::AuthorityEpoch(3),
            1,
            ResourceKind::Firewall,
        )
        .unwrap();
        let projection = PolicyProjection::Firewall {
            policy: resource.clone(),
            mode: crate::vortix_core::state::killswitch::KillSwitchMode::Auto,
            tunnels: Vec::new(),
        };
        let absent = HelperLedgerFirewall::prepared(
            resource,
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        )
        .mark_effect_pending()
        .unwrap()
        .confirm_observed(&projection)
        .unwrap();
        assert_eq!(absent.stage(), PhysicalFirewallStage::ObservedAbsent);
        let pending = absent.mark_release_pending().unwrap();
        assert_eq!(pending.stage(), PhysicalFirewallStage::AbsentReleasePending);
        assert_eq!(
            pending.restore_after_failed_release().unwrap().stage(),
            PhysicalFirewallStage::ObservedAbsent
        );
    }

    #[test]
    fn corrupt_or_ambiguous_physical_firewall_ownership_fails_closed() {
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
        let physical = HelperLedgerFirewall::prepared(
            resource.clone(),
            PhysicalFirewallBackend::LinuxNft,
            FirewallTransactionId::new([9; 32]).unwrap(),
            projection.digest(),
        );
        let record = HelperLedgerRecord::new_with_physical_firewalls(
            replay,
            vec![HelperLedgerResource::pending(resource.clone())],
            vec![HelperLedgerPolicy::new(resource, projection, None).unwrap()],
            vec![physical],
            Vec::new(),
        )
        .unwrap();
        let valid = serde_json::to_value(record).unwrap();

        let mut wrong_digest = valid.clone();
        wrong_digest["physical_firewalls"][0]["intended_digest"] = serde_json::json!(vec![8; 32]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(wrong_digest).is_err());

        let mut impossible_stage = valid.clone();
        impossible_stage["physical_firewalls"][0]["stage"] = serde_json::json!("observed_owned");
        assert!(serde_json::from_value::<HelperLedgerRecord>(impossible_stage).is_err());

        let mut wrong_generation = valid.clone();
        wrong_generation["physical_firewalls"][0]["resource"]["generation"] = serde_json::json!(2);
        assert!(serde_json::from_value::<HelperLedgerRecord>(wrong_generation).is_err());

        let mut duplicate = valid.clone();
        duplicate["physical_firewalls"]
            .as_array_mut()
            .unwrap()
            .push(valid["physical_firewalls"][0].clone());
        assert!(serde_json::from_value::<HelperLedgerRecord>(duplicate).is_err());

        let mut unknown_backend = valid.clone();
        unknown_backend["physical_firewalls"][0]["backend"] = serde_json::json!("shell");
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown_backend).is_err());

        let mut unknown_field = valid.clone();
        unknown_field["physical_firewalls"][0]["argv"] = serde_json::json!(["nft"]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown_field).is_err());

        let mut unknown_schema = valid.clone();
        unknown_schema["schema_version"] = serde_json::json!(HELPER_LEDGER_SCHEMA_VERSION + 1);
        assert!(serde_json::from_value::<HelperLedgerRecord>(unknown_schema).is_err());

        let mut oversized = valid;
        oversized["physical_firewalls"] =
            serde_json::json!(vec![serde_json::Value::Null; MAX_RESOURCE_ITEMS + 1]);
        assert!(serde_json::from_value::<HelperLedgerRecord>(oversized).is_err());
    }
}
