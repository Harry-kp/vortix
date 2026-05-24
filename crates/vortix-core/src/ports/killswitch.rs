//! `Killswitch` port — kill-switch firewall control.
//!
//! Implementations live in `vortix-platform-{macos,linux}`. The trait is
//! intentionally sync today; plan #005's async engine migration adds
//! `&CommandRunner` arguments and `async fn` where useful. For now,
//! impls reach the global runner via `vortix_process::run_to_output(...)`.

use thiserror::Error;

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

/// Firewall control for the kill switch.
///
/// Implementations block all non-VPN traffic when enabled. Methods take
/// `&str` references for the VPN interface and optional server IP.
///
/// Note: the trait stays sync in plan #003. Plan #005's async engine
/// transition adds an explicit `&CommandRunner` parameter; today impls
/// route subprocess calls through `vortix_process::run_to_output(...)`
/// (the process-global runner installed by `main.rs`).
pub trait Killswitch {
    /// Enable the kill switch by loading restrictive firewall rules.
    ///
    /// # Errors
    ///
    /// Returns [`KillswitchError`] when the firewall command fails, the
    /// caller is not root, or no backend is available.
    fn enable_blocking(vpn_interface: &str, vpn_server_ip: Option<&str>) -> Result<()>;

    /// Disable the kill switch by flushing firewall rules.
    ///
    /// # Errors
    ///
    /// Returns [`KillswitchError`] when the firewall command fails or the
    /// caller is not root.
    fn disable_blocking() -> Result<()>;
}
