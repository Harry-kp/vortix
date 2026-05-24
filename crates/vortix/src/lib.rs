//! # Vortix VPN Manager
//!
//! Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding.
//! It provides profile management and an intuitive dashboard interface.
#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]

// Internal library modules (formerly separate crates).
// Hidden from public API docs — these are implementation details.
#[doc(hidden)]
pub mod vortix_config;
#[doc(hidden)]
pub mod vortix_core;
#[doc(hidden)]
pub mod vortix_process;
#[doc(hidden)]
pub mod vortix_protocol_openvpn;
#[doc(hidden)]
pub mod vortix_protocol_wireguard;

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod vortix_platform_linux;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub mod vortix_platform_macos;
#[cfg(target_os = "windows")]
#[doc(hidden)]
pub mod vortix_platform_windows;

// Application modules
pub mod app;
pub mod cli;
pub mod config;
pub mod constants;
pub mod core;
pub mod daemon;
pub mod engine;
pub mod event;
pub mod logger;
pub mod message;
pub mod platform;
pub mod state;
pub mod theme;
pub mod tunnel;
pub mod ui;
pub mod utils;
pub mod vpn;
