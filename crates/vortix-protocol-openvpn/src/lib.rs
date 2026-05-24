//! `vortix-protocol-openvpn`: `OpenVPN` `Tunnel` impl.
//!
//! Wraps the `openvpn` binary in detached-daemon mode and watches the
//! `--log` file for `Initialization Sequence Completed` to declare the
//! tunnel established. Matches the existing engine's behaviour byte-for-byte
//! (subprocess flags, log-poll cadence, error patterns).

#![allow(clippy::missing_errors_doc)]

pub mod parser;
pub mod tunnel;

pub use parser::OvpnParsedProfile;
pub use tunnel::OvpnTunnel;
