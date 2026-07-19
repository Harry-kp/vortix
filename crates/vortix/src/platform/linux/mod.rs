//! Linux platform implementations — thin re-exports.
//!
//! The actual impl code lives in `vortix-platform-linux`.
//! Submodule aliases here keep existing `crate::platform::linux::*` paths
//! resolving until a later sweep swaps consumers over to `&Platform`.

pub use crate::vortix_platform_linux::{
    dns, firewall, interface, network_stats as network, route_table,
};
