//! Capability ports: traits that adapter crates implement to provide subprocess execution,
//! per-OS platform operations, VPN protocol drivers, etc.
//!
//! Populated by subsequent PRs in the migration. Today this module is the namespace
//! placeholder; per-port submodules land with their respective plans:
//! - `process` — `CommandRunner` (plan 002)
//! - `killswitch`, `dns`, `interface`, `network_stats`, `route_table` — capability ports (plan 003)
//! - `tunnel` — `Tunnel` trait (plan 004)
