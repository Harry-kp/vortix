//! # Vortix VPN Manager
//!
//! Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding.
//! It provides profile management and an intuitive dashboard interface.
#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]

pub mod app;
pub(crate) mod authority_lock;
pub mod cli;
pub mod config;
pub mod constants;
pub mod control;
pub mod core;
pub mod event;
pub mod hooks;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod linux;
pub mod logger;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub mod macos;
pub mod message;
#[doc(hidden)]
pub mod openvpn;
pub mod platform;
#[doc(hidden)]
pub mod process;
pub mod theme;
pub mod ui;
pub mod utils;
#[doc(hidden)]
pub mod wireguard;
