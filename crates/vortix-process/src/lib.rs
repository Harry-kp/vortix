//! `vortix-process`: concrete `CommandRunner` implementations (`RealRunner`, `MockRunner`)
//! for the trait declared in `vortix-core::ports::process`.
//!
//! Owns the `tokio` + `tracing` dependency surface so that `vortix-core` stays runtime-free.
//! See `docs/plans/2026-05-24-002-feat-commandrunner-port-plan.md` for the implementation
//! plan; this crate ships as a stub in plan 001's workspace skeleton.
