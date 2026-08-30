//! Canonical DNS-policy posture shown by the Security Guard.
//!
//! This status comes from the control owner's generation-fenced platform
//! readback. It deliberately does not infer a leak from a recursive resolver's
//! public egress address: private forwarders normally recurse through a
//! different public address, and a direct query to the configured server does
//! not prove which resolver the operating system used.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsProtectionStatus {
    /// No connected tunnel currently requires a DNS-policy verdict.
    #[default]
    NotActive,
    /// The exact current-generation DNS policy was applied and read back.
    Verified,
    /// A tunnel is connected, but current-generation DNS readback is absent.
    Unverified,
}
