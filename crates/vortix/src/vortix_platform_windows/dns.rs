//! Windows DNS stub (plan 008 U4).
//!
//! Real impl would query Windows DNS via `Get-DnsClientServerAddress`
//! or the `windows-sys::Win32::NetworkManagement::Dns` APIs. Today it
//! returns `None`.

use crate::vortix_core::ports::dns::DnsResolver;

#[derive(Debug, Clone, Default)]
pub struct WindowsDns;

impl DnsResolver for WindowsDns {
    fn get_dns_server() -> Option<String> {
        None
    }
}
