//! Restart-safe DNS mutation owned by the privileged helper.

use super::dns::DnsPolicy;

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
}
