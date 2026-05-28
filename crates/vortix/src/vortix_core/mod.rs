//! `vortix-core`: pure library defining the engine FSM, capability port traits, event schema,
//! and shared error types for the vortix VPN manager.
//!
//! This crate is intentionally free of TUI, process-runtime, clock, and OS dependencies.
//! Concrete adapters (subprocess execution, OS-specific platform impls, protocol drivers,
//! configuration storage) live in sibling crates and implement the traits defined here.
//!
//! See `docs/ideation/2026-05-24-vortix-architecture-ideation.md` for the architectural
//! migration context and `docs/brainstorms/2026-05-24-*-requirements.md` for the
//! per-concern requirements.

#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]

pub mod cidr;
pub mod cidr_subtract;
pub mod engine;
pub mod ipc;
pub mod journal;
pub mod ports;
pub mod profile;
pub mod secret_file;
pub mod state;

pub use cidr::{claims_default_route_v4, claims_default_route_v6, Cidr};
pub use cidr_subtract::cidr_subtract;
