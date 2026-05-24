//! # Vortix VPN Manager
//!
//! Terminal UI for `WireGuard` and `OpenVPN` with real-time telemetry and leak guarding.
//! It provides profile management and an intuitive dashboard interface.
#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]

pub mod app;
pub mod cli;
pub mod config;
pub mod constants;
pub mod core;
pub mod engine;
pub mod event;
pub mod logger;
pub mod message;
pub mod platform;
pub mod state;
pub mod theme;
pub mod ui;
pub mod utils;
pub mod vpn;
