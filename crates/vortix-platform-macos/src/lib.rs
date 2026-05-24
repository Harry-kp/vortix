//! `vortix-platform-macos`: macOS platform adapters.
//!
//! Empty stub for plan 001's minimal-relocation strategy. Plan 003 (capability ports)
//! moves the existing `src/platform/macos/*` code into this crate after first relocating
//! the `Firewall` / `NetworkStatsProvider` / etc. trait definitions into `vortix-core`,
//! which breaks the transitional two-way path dep.
