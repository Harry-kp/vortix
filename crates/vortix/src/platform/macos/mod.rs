//! macOS platform implementations — thin re-exports.
//!
//! The actual impl code lives in `vortix-platform-macos` per plan 003 U1/U2.
//! Submodule aliases here keep existing `crate::platform::macos::*` paths
//! resolving until plan 003 U7 swaps consumers over to `&Platform`.

pub use crate::vortix_platform_macos::{
    dns, firewall, interface, network_stats as network, route_table,
};
