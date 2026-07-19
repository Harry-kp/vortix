//! macOS platform implementations — thin re-exports.
//!
//! The actual impl code lives in `vortix-platform-macos`.
//! Submodule aliases here keep existing `crate::platform::macos::*` paths
//! resolving until a later sweep swaps consumers over to `&Platform`.

pub use crate::vortix_platform_macos::{
    dns, firewall, interface, network_stats as network, route_table,
};
