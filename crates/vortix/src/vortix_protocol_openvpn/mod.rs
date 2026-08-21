//! `vortix-protocol-openvpn`: `OpenVPN` `Tunnel` impl.
//!
//! Runs the `openvpn` binary as a custodian-owned foreground child and watches the
//! `--log` file for `Initialization Sequence Completed` to declare the
//! tunnel established.

#![allow(clippy::missing_errors_doc)]

pub mod parser;
pub mod tunnel;

pub(crate) mod execution;
pub(crate) mod management;
pub(crate) mod push;

pub use parser::OvpnParsedProfile;
pub use tunnel::{OvpnDnsEvidence, OvpnTunnel};
