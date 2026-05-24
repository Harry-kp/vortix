//! Windows kill-switch stub (plan 008 U4).
//!
//! Real impl would drive `netsh advfirewall` or the Windows Filtering
//! Platform via `windows-sys`. Today this returns `CommandFailed("not
//! supported on Windows yet")` for both engage and disengage.

use crate::vortix_core::ports::killswitch::{Killswitch, KillswitchError, Result};

#[derive(Debug, Clone, Default)]
pub struct WindowsFirewall;

impl Killswitch for WindowsFirewall {
    fn enable_blocking(_vpn_interface: &str, _vpn_server_ip: Option<&str>) -> Result<()> {
        Err(KillswitchError::CommandFailed(
            "Windows kill switch is not implemented yet (plan 008 U4 stub)".into(),
        ))
    }

    fn disable_blocking() -> Result<()> {
        Err(KillswitchError::CommandFailed(
            "Windows kill switch is not implemented yet (plan 008 U4 stub)".into(),
        ))
    }
}
