//! `vortix-protocol-wireguard`: `WireGuard` `Tunnel` impl.
//!
//! Wraps `wg-quick` for lifecycle and owns machine-readable `wg show` status
//! parsing. Scanner and control code consume typed observations only.

#![allow(clippy::missing_errors_doc)]

pub mod parser;
pub mod tunnel;

pub use parser::WgParsedProfile;
pub use tunnel::{select_health_probe, WgTunnel};
