//! `Killswitch` port — kill-switch firewall control.
//!
//! Implementations live in `vortix-platform-{macos,linux,windows}`. The
//! trait is intentionally sync today; plan #005's async engine migration
//! adds `&CommandRunner` arguments and `async fn` where useful. For now,
//! impls reach the global runner via `crate::vortix_process::run_to_output(...)`.
//!
//! Plan multi-connection U8 replaces the single-tunnel `enable_blocking`
//! signature with `enable_blocking_multi`, which accepts a slice of
//! [`ActiveTunnelInfo`] — one per active tunnel — so the platform can
//! synthesize a multi-interface ruleset in a single restore call.

use std::net::IpAddr;

use thiserror::Error;

use crate::vortix_core::cidr::Cidr;

/// Result alias for kill-switch operations.
pub type Result<T> = std::result::Result<T, KillswitchError>;

/// Errors that can occur during kill-switch operations.
#[derive(Debug, Error)]
pub enum KillswitchError {
    /// A firewall subprocess returned a non-zero exit or otherwise failed.
    #[error("firewall command failed: {0}")]
    CommandFailed(String),
    /// I/O error (reading/writing pf config, opening sockets, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The caller is not running as root and the operation requires root.
    #[error("kill switch requires root privileges")]
    NotRoot,
    /// No firewall backend is available on this host (Linux only — neither
    /// `iptables` nor `nft` is on PATH).
    #[error("no firewall backend available on this host")]
    NoBackendAvailable,
}

/// Per-tunnel state needed to synthesise multi-interface killswitch
/// rules. The platform impl uses the interface name for interface-allow
/// rules, the server IPs for reconnect-allow rules, and the declared
/// CIDRs to subtract from the RFC1918 base when this tunnel is a
/// secondary.
///
/// Primary tunnels (claiming the default route, `is_primary == true`)
/// do **not** contribute to RFC1918 subtraction — their interface allow
/// rule covers all egress, and subtracting `0.0.0.0/0` would strip
/// loopback. See plan unit U8 / Q-DEF-9 resolution D-6.
#[derive(Debug, Clone)]
pub struct ActiveTunnelInfo {
    /// VPN tunnel interface name, e.g. `"utun3"` (macOS) or `"wg0"` (Linux).
    pub interface: String,
    /// Server IPs to allow for reconnection. May be empty if the tunnel
    /// has no externally observable server endpoint (mock / dev).
    pub server_ips: Vec<IpAddr>,
    /// CIDRs this tunnel declares as its routed scope. Used only for
    /// secondaries: subtracted from the RFC1918 base so traffic to those
    /// nets cannot escape onto the underlay.
    pub declared_cidrs: Vec<Cidr>,
    /// `true` when this tunnel claims the default route (primary).
    /// Primaries are excluded from RFC1918 subtraction.
    pub is_primary: bool,
}

/// Firewall control for the kill switch.
///
/// Implementations block all non-VPN traffic when enabled. The
/// multi-tunnel form lets the synthesizer install allow rules for every
/// active tunnel in a single atomic ruleset.
///
/// Note: the trait stays sync in plan #003. Plan #005's async engine
/// transition adds an explicit `&CommandRunner` parameter; today impls
/// route subprocess calls through `crate::vortix_process::run_to_output(...)`
/// (the process-global runner installed by `main.rs`).
pub trait Killswitch {
    /// Enable the kill switch with a ruleset covering every tunnel in
    /// `active`. An empty slice installs a base block-all ruleset with
    /// no per-tunnel allow rules (used during early bring-up and on
    /// hard-fail Armed states).
    ///
    /// # Errors
    ///
    /// Returns [`KillswitchError`] when the firewall command fails, the
    /// caller is not root, or no backend is available.
    fn enable_blocking_multi(active: &[ActiveTunnelInfo]) -> Result<()>;

    /// Disable the kill switch by flushing firewall rules.
    ///
    /// # Errors
    ///
    /// Returns [`KillswitchError`] when the firewall command fails or the
    /// caller is not root.
    fn disable_blocking() -> Result<()>;
}
