//! Linux root-helper firewall adapter.
//!
//! Activation stays closed until the nftables and guarded dual-family
//! iptables transaction implementations can satisfy exact restart read-back.

use crate::vortix_core::ports::killswitch::ActiveTunnelInfo;
use crate::vortix_core::ports::owned_firewall::{OwnedFirewall, OwnedFirewallError};

pub(crate) struct LinuxOwnedFirewall;

impl OwnedFirewall for LinuxOwnedFirewall {
    fn apply_blocking(&mut self, _active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError> {
        Err(OwnedFirewallError::FailedBeforeEffect)
    }

    fn clear(&mut self) -> Result<(), OwnedFirewallError> {
        Err(OwnedFirewallError::FailedBeforeEffect)
    }

    fn audit_blocking(&mut self, _active: &[ActiveTunnelInfo]) -> Result<(), OwnedFirewallError> {
        Err(OwnedFirewallError::FailedBeforeEffect)
    }

    fn audit_absent(&mut self) -> Result<(), OwnedFirewallError> {
        Err(OwnedFirewallError::FailedBeforeEffect)
    }

    fn audit_recovery(
        &mut self,
        _blocking_candidates: &[Vec<ActiveTunnelInfo>],
        _allow_absent: bool,
    ) -> Result<(), OwnedFirewallError> {
        Err(OwnedFirewallError::FailedBeforeEffect)
    }
}
