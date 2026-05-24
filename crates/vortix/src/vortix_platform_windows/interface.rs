//! Windows interface stub (plan 008 U4).
//!
//! Real impl would query `Get-NetAdapter` / IP Helper APIs. Today
//! every method reports "not found" — the FSM treats "no interface"
//! as a normal disconnected state, so this stub doesn't crash anything.

use crate::vortix_core::ports::interface::Interface;

#[derive(Debug, Clone, Default)]
pub struct WindowsInterface;

impl Interface for WindowsInterface {
    fn check_wireguard_interface(_name: &str) -> bool {
        false
    }

    fn resolve_wireguard_interface(_name: &str) -> Option<String> {
        None
    }

    fn get_wireguard_pid(_interface: &str) -> Option<u32> {
        None
    }

    fn get_interface_info(_interface: &str) -> (String, String) {
        (String::new(), String::new())
    }
}
