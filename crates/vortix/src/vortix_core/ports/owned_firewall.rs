//! Root-helper firewall port.
//!
//! This port is deliberately narrower than [`super::killswitch::Killswitch`]:
//! the privileged helper may mutate only Vortix's fixed, platform-owned
//! policy object and must classify failures around the first possible effect.

use super::killswitch::ActiveTunnelInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedFirewallError {
    FailedBeforeEffect,
    EffectMayHaveApplied,
}

pub(crate) trait OwnedFirewall: Send {
    fn apply_blocking(&mut self, active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError>;

    fn clear(&mut self) -> Result<(), OwnedFirewallError>;

    fn audit_blocking(&mut self, active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError>;

    fn audit_absent(&mut self) -> Result<(), OwnedFirewallError>;

    fn audit_recovery(
        &mut self,
        blocking_candidates: &[Vec<ActiveTunnelInfo>],
        allow_absent: bool,
    ) -> Result<(), OwnedFirewallError>;
}
