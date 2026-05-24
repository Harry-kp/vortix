//! `vortix-protocol-wireguard`: `WireGuard` `Tunnel` impl.
//!
//! Wraps `wg-quick` for connect/disconnect and uses the binary-side scanner
//! for status readout (until plan #005's async engine migration brings the
//! status path through this crate as well).

#![allow(clippy::missing_errors_doc)]

pub mod parser;
pub mod tunnel;

pub use parser::WgParsedProfile;
pub use tunnel::WgTunnel;
