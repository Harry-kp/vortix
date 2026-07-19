//! Windows kill-switch stub.
//!
//! Real impl would drive `netsh advfirewall` or the Windows Filtering
//! Platform via `windows-sys`. Today this returns `Ok(())` from
//! `enable_blocking_multi` (no-op stub) so the rest of the engine can
//! exercise its rule-synthesis path under tests and on developer
//! workstations.

use crate::vortix_core::ports::killswitch::{
    ActiveTunnelInfo, Killswitch, KillswitchError, Result,
};

#[derive(Debug, Clone, Default)]
pub struct WindowsFirewall;

impl Killswitch for WindowsFirewall {
    fn enable_blocking_multi(_active: &[ActiveTunnelInfo]) -> Result<()> {
        // Stub — the Windows backend is future work. Returning Ok lets
        // the engine progress on Windows; no actual rules are installed.
        Ok(())
    }

    fn disable_blocking() -> Result<()> {
        Err(KillswitchError::CommandFailed(
            "Windows kill switch is not implemented yet".into(),
        ))
    }
}
