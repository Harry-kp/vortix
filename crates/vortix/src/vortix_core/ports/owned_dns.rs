//! Restart-safe DNS mutation owned by the privileged helper.

use super::dns::DnsPolicy;
use crate::vortix_core::privileged::{PhysicalDnsBackend, PhysicalDnsPrior};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "effect classification is exercised only by an implemented target adapter"
)]
pub(crate) enum OwnedDnsError {
    FailedBeforeEffect,
    EffectMayHaveApplied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "each backend variant is constructed only on its target operating system"
)]
pub(crate) enum OwnedDnsBackend {
    LinuxPendingPhysicalLedger,
    MacOsResolverFiles,
}

#[derive(Debug, Clone, Copy)]
#[allow(
    dead_code,
    reason = "the disabled Linux adapter never consumes the expected prior policy"
)]
pub(crate) enum ExpectedDnsState<'a> {
    Absent,
    Applied(&'a DnsPolicy),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedDnsLink {
    interface: String,
    prior: PhysicalDnsPrior,
}

impl OwnedDnsLink {
    pub(crate) const fn new(interface: String, prior: PhysicalDnsPrior) -> Self {
        Self { interface, prior }
    }

    pub(crate) fn interface(&self) -> &str {
        &self.interface
    }

    pub(crate) const fn prior(&self) -> &PhysicalDnsPrior {
        &self.prior
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedOwnedDns {
    backend: PhysicalDnsBackend,
    links: Vec<OwnedDnsLink>,
}

impl PreparedOwnedDns {
    pub(crate) const fn new(backend: PhysicalDnsBackend, links: Vec<OwnedDnsLink>) -> Self {
        Self { backend, links }
    }

    pub(crate) const fn backend(&self) -> PhysicalDnsBackend {
        self.backend
    }

    pub(crate) fn links(&self) -> &[OwnedDnsLink] {
        &self.links
    }
}

#[derive(Debug, Clone)]
pub(crate) struct OwnedDnsRecoveryCandidate {
    policy: DnsPolicy,
    physical: PreparedOwnedDns,
}

impl OwnedDnsRecoveryCandidate {
    pub(crate) const fn new(policy: DnsPolicy, physical: PreparedOwnedDns) -> Self {
        Self { policy, physical }
    }

    pub(crate) const fn policy(&self) -> &DnsPolicy {
        &self.policy
    }

    pub(crate) const fn physical(&self) -> &PreparedOwnedDns {
        &self.physical
    }
}

pub(crate) trait OwnedDns: Send {
    fn backend(&self) -> OwnedDnsBackend;

    fn apply(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
    ) -> Result<(), OwnedDnsError>;

    fn audit(&mut self, desired: &DnsPolicy) -> Result<(), OwnedDnsError>;

    fn audit_absent(&mut self) -> Result<(), OwnedDnsError>;

    /// Reconcile a crash-interrupted replacement only when every managed
    /// artifact is an exact intended/prior generation member (or absent).
    fn recover_pending(
        &mut self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
    ) -> Result<(), OwnedDnsError>;

    fn audit_recovery(
        &mut self,
        candidates: &[DnsPolicy],
        allow_absent: bool,
    ) -> Result<(), OwnedDnsError>;

    fn prepare_physical(
        &mut self,
        _desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        inherited: &[OwnedDnsLink],
    ) -> Result<PreparedOwnedDns, OwnedDnsError> {
        if self.backend() != OwnedDnsBackend::MacOsResolverFiles
            || inherited
                .iter()
                .any(|link| !matches!(link.prior(), PhysicalDnsPrior::MacOsResolverFiles))
        {
            return Err(OwnedDnsError::FailedBeforeEffect);
        }
        match expected {
            ExpectedDnsState::Absent => self.audit_absent()?,
            ExpectedDnsState::Applied(prior) => self.audit(prior)?,
        }
        Ok(PreparedOwnedDns::new(
            PhysicalDnsBackend::MacOsResolverFiles,
            Vec::new(),
        ))
    }

    fn apply_physical(
        &mut self,
        desired: &DnsPolicy,
        expected: ExpectedDnsState<'_>,
        prepared: &PreparedOwnedDns,
        _recovered: &[PreparedOwnedDns],
    ) -> Result<(), OwnedDnsError> {
        if prepared.backend() != PhysicalDnsBackend::MacOsResolverFiles
            || !prepared.links().is_empty()
        {
            return Err(OwnedDnsError::FailedBeforeEffect);
        }
        self.apply(desired, expected)
    }

    fn audit_physical(
        &mut self,
        desired: &DnsPolicy,
        prepared: &PreparedOwnedDns,
    ) -> Result<(), OwnedDnsError> {
        if prepared.backend() != PhysicalDnsBackend::MacOsResolverFiles
            || !prepared.links().is_empty()
        {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        self.audit(desired)
    }

    fn recover_pending_physical(
        &mut self,
        desired: &DnsPolicy,
        prior: Option<&DnsPolicy>,
        prepared: &PreparedOwnedDns,
        recovered: &[PreparedOwnedDns],
    ) -> Result<(), OwnedDnsError> {
        if prepared.backend() != PhysicalDnsBackend::MacOsResolverFiles
            || !prepared.links().is_empty()
            || recovered.iter().any(|candidate| {
                candidate.backend() != PhysicalDnsBackend::MacOsResolverFiles
                    || !candidate.links().is_empty()
            })
        {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        self.recover_pending(desired, prior)
    }

    fn audit_recovery_physical(
        &mut self,
        candidates: &[OwnedDnsRecoveryCandidate],
        allow_absent: bool,
    ) -> Result<(), OwnedDnsError> {
        if candidates.iter().any(|candidate| {
            candidate.physical().backend() != PhysicalDnsBackend::MacOsResolverFiles
                || !candidate.physical().links().is_empty()
        }) {
            return Err(OwnedDnsError::EffectMayHaveApplied);
        }
        let policies = candidates
            .iter()
            .map(OwnedDnsRecoveryCandidate::policy)
            .cloned()
            .collect::<Vec<_>>();
        self.audit_recovery(&policies, allow_absent)
    }

    /// Prove that the retained generation is effective and every obsolete
    /// backend artifact is either subsumed by it or restored to its captured
    /// prior state before logical ownership is released.
    fn audit_release_physical(
        &mut self,
        retained: &OwnedDnsRecoveryCandidate,
        obsolete: &[OwnedDnsRecoveryCandidate],
    ) -> Result<(), OwnedDnsError> {
        if std::iter::once(retained).chain(obsolete).any(|candidate| {
            candidate.physical().backend() != PhysicalDnsBackend::MacOsResolverFiles
                || !candidate.physical().links().is_empty()
        }) {
            return Err(OwnedDnsError::FailedBeforeEffect);
        }
        self.audit(retained.policy())
            .map_err(|_| OwnedDnsError::FailedBeforeEffect)
    }
}
