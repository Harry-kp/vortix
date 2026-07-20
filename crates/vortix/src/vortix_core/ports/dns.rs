//! DNS inspection and policy ports.
//!
//! Protocol adapters report requested resolvers; this module computes one
//! protocol-neutral policy from the current tunnel roles. Platform adapters
//! are the only writers of resolver state.

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::vortix_core::profile::ProfileId;

/// Read-only DNS resolver inspection.
pub trait DnsResolver {
    /// Get the current system DNS server address, if any.
    fn get_dns_server() -> Option<String>;
}

/// Resolver settings requested by one protocol profile or live session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRequest {
    pub servers: Vec<IpAddr>,
    #[serde(default)]
    pub search_domains: Vec<String>,
}

impl DnsRequest {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

/// The kernel-derived routing role of a connected tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsTunnelRole {
    Primary,
    Secondary,
}

/// All policy inputs for one connected tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTunnelIntent {
    pub profile_id: ProfileId,
    pub interface: String,
    pub role: DnsTunnelRole,
    pub request: DnsRequest,
}

/// Capabilities of the selected platform DNS backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsPlatformCapabilities {
    /// The backend can route named DNS suffixes to a secondary tunnel.
    pub scoped_domains: bool,
}

/// Effective resolver scope assigned to one tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsScope {
    /// Resolve all names through the primary tunnel.
    CatchAll,
    /// Resolve only the listed suffixes through this secondary tunnel.
    Scoped { domains: Vec<String> },
    /// Do not register this tunnel's requested resolver globally.
    Suppressed,
}

/// One entry in a complete desired DNS policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAssignment {
    pub profile_id: ProfileId,
    pub interface: String,
    pub servers: Vec<IpAddr>,
    /// Normalized suffixes the resolver should use for unqualified names.
    /// This is independent of routing scope: a catch-all primary may still
    /// provide search domains, while a secondary uses them as scoped routes.
    #[serde(default)]
    pub search_domains: Vec<String>,
    pub scope: DnsScope,
}

/// A complete resolver policy for one monotonic desired generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicy {
    pub generation: u64,
    pub assignments: Vec<DnsAssignment>,
}

impl DnsPolicy {
    /// Compute a complete policy. At most one tunnel may own catch-all DNS.
    pub fn compute(
        generation: u64,
        intents: &[DnsTunnelIntent],
        capabilities: DnsPlatformCapabilities,
    ) -> Result<Self, DnsPolicyError> {
        let primary_count = intents
            .iter()
            .filter(|intent| intent.role == DnsTunnelRole::Primary)
            .count();
        if primary_count > 1 {
            return Err(DnsPolicyError::MultiplePrimaries);
        }

        let mut assignments = intents
            .iter()
            .filter(|intent| !intent.request.is_empty())
            .map(|intent| {
                let scope = match intent.role {
                    DnsTunnelRole::Primary => DnsScope::CatchAll,
                    DnsTunnelRole::Secondary if capabilities.scoped_domains => {
                        let domains = normalized_domains(&intent.request.search_domains);
                        if domains.is_empty() {
                            DnsScope::Suppressed
                        } else {
                            DnsScope::Scoped { domains }
                        }
                    }
                    DnsTunnelRole::Secondary => DnsScope::Suppressed,
                };
                DnsAssignment {
                    profile_id: intent.profile_id.clone(),
                    interface: intent.interface.clone(),
                    servers: intent.request.servers.clone(),
                    search_domains: normalized_domains(&intent.request.search_domains),
                    scope,
                }
            })
            .collect::<Vec<_>>();
        assignments.sort_by(|a, b| a.profile_id.as_str().cmp(b.profile_id.as_str()));
        Ok(Self {
            generation,
            assignments,
        })
    }

    /// Compare desired content while ignoring its generation number.
    #[must_use]
    pub fn same_content(&self, other: &Self) -> bool {
        self.assignments == other.assignments
    }
}

fn normalized_domains(domains: &[String]) -> Vec<String> {
    let mut domains = domains
        .iter()
        .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .collect::<Vec<_>>();
    domains.sort();
    domains.dedup();
    domains
}

/// A platform resource created by Vortix for one desired generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsOwnedResource {
    pub generation: u64,
    pub id: String,
    pub profile_id: ProfileId,
    pub interface: String,
}

/// Truthful result of applying or releasing one desired generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsEffectiveStatus {
    Released,
    Applied,
    Degraded,
}

/// Requested, effective, and ownership truth retained for reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEffectiveState {
    pub requested_generation: u64,
    pub applied_generation: Option<u64>,
    pub status: DnsEffectiveStatus,
    pub owned: Vec<DnsOwnedResource>,
    pub errors: Vec<String>,
}

impl Default for DnsEffectiveState {
    fn default() -> Self {
        Self {
            requested_generation: 0,
            applied_generation: None,
            status: DnsEffectiveStatus::Released,
            owned: Vec::new(),
            errors: Vec::new(),
        }
    }
}

/// Platform mutation seam consumed by the global policy coordinator.
pub trait DnsPolicyAdapter {
    fn capabilities(&self) -> DnsPlatformCapabilities;

    fn apply(
        &self,
        desired: &DnsPolicy,
        previous_desired: Option<&DnsPolicy>,
        previous_effective: &DnsEffectiveState,
    ) -> DnsEffectiveState;

    /// Prove that the platform still matches an already-applied policy
    /// without mutating resolver state.
    fn verify(&self, desired: &DnsPolicy, effective: &DnsEffectiveState)
        -> Result<(), Vec<String>>;
}

const DNS_PROOF_MAX_AGE: Duration = Duration::from_secs(5);

/// Monotonic coordinator state shared by local CLI/TUI and the later service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsPolicyCoordinator {
    desired: Option<DnsPolicy>,
    effective: DnsEffectiveState,
    #[serde(default)]
    verified_generation: Option<u64>,
    #[serde(default)]
    verified_digest: Option<u64>,
    #[serde(default)]
    verified_at_unix_ms: Option<u64>,
    #[serde(skip)]
    verified_at_monotonic: Option<Instant>,
    /// Persisted user-owned state is useful as advisory intent, but must not
    /// authorize cleanup or rollback of privileged platform resources.
    #[serde(skip)]
    runtime_authority: bool,
}

impl Default for DnsPolicyCoordinator {
    fn default() -> Self {
        Self {
            desired: None,
            effective: DnsEffectiveState::default(),
            verified_generation: None,
            verified_digest: None,
            verified_at_unix_ms: None,
            verified_at_monotonic: None,
            runtime_authority: true,
        }
    }
}

impl DnsPolicyCoordinator {
    #[must_use]
    pub fn desired(&self) -> Option<&DnsPolicy> {
        self.desired.as_ref()
    }

    #[must_use]
    pub fn effective(&self) -> &DnsEffectiveState {
        &self.effective
    }

    /// Recover the last requested resolver intent for same-boot/process
    /// restart reconciliation. Live protocol evidence replaces this cache.
    #[must_use]
    pub fn request_for(&self, profile_id: &ProfileId) -> Option<DnsRequest> {
        let assignment = self
            .desired
            .as_ref()?
            .assignments
            .iter()
            .find(|assignment| &assignment.profile_id == profile_id)?;
        Some(DnsRequest {
            servers: assignment.servers.clone(),
            search_domains: assignment.search_domains.clone(),
        })
    }

    /// Persisted effective state is recovery evidence, never fresh platform
    /// verification. Force the next reconcile to reapply/read back.
    pub fn invalidate_effective(&mut self, reason: impl Into<String>) {
        self.effective.status = DnsEffectiveStatus::Degraded;
        self.effective.errors = vec![reason.into()];
        self.clear_verification();
    }

    /// Strip all privileged ownership claims after loading user-controlled
    /// persisted state. Desired intent remains advisory for recovery.
    pub fn discard_persisted_authority(&mut self) {
        self.runtime_authority = false;
        self.effective.applied_generation = None;
        self.effective.owned.clear();
        self.invalidate_effective("persisted DNS state requires platform read-back");
    }

    /// Force a read-only platform proof on the next unchanged reconcile.
    pub fn invalidate_verification(&mut self) {
        self.clear_verification();
    }

    /// Recompute and apply the entire policy. Identical effective content is
    /// a no-op; degraded content is retried without inventing a generation.
    pub fn reconcile<A: DnsPolicyAdapter>(
        &mut self,
        intents: &[DnsTunnelIntent],
        adapter: &A,
    ) -> Result<&DnsEffectiveState, DnsPolicyError> {
        self.reconcile_durable(intents, adapter, |_| Ok::<(), std::convert::Infallible>(()))
    }

    /// Reconcile with a write-ahead desired record and a durable effective
    /// receipt. No platform mutation occurs unless the pending generation is
    /// safely persisted first.
    pub fn reconcile_durable<A, F, E>(
        &mut self,
        intents: &[DnsTunnelIntent],
        adapter: &A,
        mut persist: F,
    ) -> Result<&DnsEffectiveState, DnsPolicyError>
    where
        A: DnsPolicyAdapter,
        F: FnMut(&Self) -> Result<(), E>,
        E: std::fmt::Display,
    {
        let next_generation = self
            .desired
            .as_ref()
            .map_or(1, |policy| policy.generation.saturating_add(1));
        let candidate = DnsPolicy::compute(next_generation, intents, adapter.capabilities())?;

        let unchanged = self
            .desired
            .as_ref()
            .is_some_and(|current| current.same_content(&candidate));
        if unchanged && self.effective.status != DnsEffectiveStatus::Degraded {
            let desired = self.desired.as_ref().expect("unchanged policy exists");
            if self.has_fresh_proof(desired) {
                return Ok(&self.effective);
            }
            match adapter.verify(desired, &self.effective) {
                Ok(()) => self.record_verification(),
                Err(errors) => {
                    self.effective.status = DnsEffectiveStatus::Degraded;
                    self.effective.errors = errors;
                    self.clear_verification();
                }
            }
            persist(self).map_err(|error| {
                self.mark_persistence_failure(format!("persist DNS verification: {error}"));
                DnsPolicyError::Persistence(error.to_string())
            })?;
            return Ok(&self.effective);
        }

        let desired = if unchanged {
            self.desired.clone().expect("unchanged policy exists")
        } else {
            candidate
        };
        let previous_desired = self.desired.clone();
        let previous_effective = self.effective.clone();
        let previous_authority = self.runtime_authority;

        // Write-ahead state is deliberately degraded: it records intent but
        // never claims that a privileged platform mutation completed.
        self.desired = Some(desired);
        self.effective.requested_generation = self
            .desired
            .as_ref()
            .expect("desired policy was installed")
            .generation;
        self.effective.status = DnsEffectiveStatus::Degraded;
        self.effective.errors = vec!["DNS policy generation pending platform apply".into()];
        self.clear_verification();
        if let Err(error) = persist(self) {
            self.mark_persistence_failure(format!("persist DNS write-ahead: {error}"));
            return Err(DnsPolicyError::Persistence(error.to_string()));
        }

        let desired = self.desired.clone().expect("desired policy was installed");
        let trusted_previous = previous_authority
            .then_some(previous_desired.as_ref())
            .flatten();
        let effective = adapter.apply(&desired, trusted_previous, &previous_effective);
        self.effective = effective;
        self.runtime_authority = true;
        if matches!(
            self.effective.status,
            DnsEffectiveStatus::Applied | DnsEffectiveStatus::Released
        ) {
            self.record_verification();
        }

        if let Err(error) = persist(self) {
            let rollback_policy = previous_desired.clone().unwrap_or_else(|| DnsPolicy {
                generation: desired.generation.saturating_add(1),
                assignments: Vec::new(),
            });
            let rollback = adapter.apply(&rollback_policy, Some(&desired), &self.effective);
            self.desired = previous_desired;
            self.effective = rollback;
            self.runtime_authority = previous_authority;
            self.mark_persistence_failure(format!(
                "persist DNS effective receipt: {error}; platform rollback attempted"
            ));
            let _ = persist(self);
            return Err(DnsPolicyError::Persistence(error.to_string()));
        }
        Ok(&self.effective)
    }

    fn has_fresh_proof(&self, desired: &DnsPolicy) -> bool {
        self.verified_generation == Some(desired.generation)
            && self.verified_digest == Some(policy_digest(desired))
            && self.verified_at_unix_ms.is_some()
            && self
                .verified_at_monotonic
                .is_some_and(|verified| verified.elapsed() <= DNS_PROOF_MAX_AGE)
    }

    fn record_verification(&mut self) {
        let Some(desired) = self.desired.as_ref() else {
            return;
        };
        self.verified_generation = Some(desired.generation);
        self.verified_digest = Some(policy_digest(desired));
        self.verified_at_unix_ms = Some(now_unix_ms());
        self.verified_at_monotonic = Some(Instant::now());
    }

    fn clear_verification(&mut self) {
        self.verified_generation = None;
        self.verified_digest = None;
        self.verified_at_unix_ms = None;
        self.verified_at_monotonic = None;
    }

    fn mark_persistence_failure(&mut self, error: String) {
        self.effective.status = DnsEffectiveStatus::Degraded;
        self.effective.errors = vec![error];
        self.clear_verification();
    }
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn policy_digest(policy: &DnsPolicy) -> u64 {
    let bytes = serde_json::to_vec(policy).unwrap_or_default();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// Pure policy validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DnsPolicyError {
    #[error("DNS policy has more than one primary tunnel")]
    MultiplePrimaries,
    #[error("DNS policy persistence failed: {0}")]
    Persistence(String),
}
