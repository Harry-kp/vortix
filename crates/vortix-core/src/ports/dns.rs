//! `DnsResolver` port — query the system DNS server.

/// Read-only DNS resolver inspection.
///
/// Implementations query whichever OS API or config file the host uses to
/// resolve names. The current callers only need to know the primary
/// nameserver; future ports may grow `apply`/`restore` once vortix wants to
/// rewrite the system resolver.
pub trait DnsResolver {
    /// Get the current system DNS server address, if any.
    fn get_dns_server() -> Option<String>;
}
