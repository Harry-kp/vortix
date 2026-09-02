//! One binary for the integration suite.
//!
//! Every module here was its own `tests/*.rs` target, and cargo links each target
//! against the whole `vortix` rlib. Grouping them collapses 17 link steps into one.
//!
//! A file in this directory with no `mod` line below compiles into nothing and its
//! tests silently stop running. See docs/performance.md for which suites stay as
//! their own target, and why.

#[path = "../support/control_scenarios.rs"]
mod control_scenarios;

mod cli_profile_mutation;
mod control_contract;
mod control_parity;
mod control_reconcile;
mod control_recovery;
mod control_service;
mod daemon_ipc;
mod dns_policy;
mod helper_contract;
mod helper_integration;
mod hooks_integration;
mod json_v2_envelope;
mod openvpn_credential_store;
mod privileged_contract;
mod profile_identity;
mod telemetry_behavior_parity;
mod wireguard_handshake_health;
