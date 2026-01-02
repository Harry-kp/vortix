//! Application-wide constants and configuration values.
//!
//! This module defines all static configuration values used throughout Vortix,
//! including timing intervals, API endpoints, file paths, and UI messages.

#![allow(dead_code)]
use std::time::Duration;

// === Application Metadata ===

/// Application name used in logging and directories.
pub const APP_NAME: &str = "vortix";
/// Current application version from Cargo.toml.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// === Timing Configuration ===

/// UI refresh rate in milliseconds.
pub const DEFAULT_TICK_RATE: u64 = 1000;
/// Interval between telemetry API calls.
pub const TELEMETRY_POLL_RATE: Duration = Duration::from_secs(10);

// === Path Configuration ===

/// Name of the configuration directory under ~/.config/
pub const CONFIG_DIR_NAME: &str = "vortix";
/// Name of the profiles subdirectory.
pub const PROFILES_DIR_NAME: &str = "profiles";

// === Telemetry API Endpoints ===

/// API endpoint for IP address and ISP lookup.
pub const IP_TELEMETRY_API: &str = "https://ipinfo.io/json";
/// API endpoint for IPv6 leak detection.
pub const IPV6_CHECK_API: &str = "https://api6.ipify.org";
/// Target host for latency measurements.
pub const PING_TARGET: &str = "1.1.1.1";

// === UI Messages ===

/// Initialization message template.
pub const MSG_INIT: &str = "INIT: VORTIX v{} starting...";
/// Backend initialization message.
pub const MSG_BACKEND_INIT: &str = "IO: Initializing VPN backend...";
/// Ready state message.
pub const MSG_READY: &str = "SUCCESS: System active. Press [?] for help.";
/// Connection in progress message template.
pub const MSG_CONNECTING: &str = "Connecting to {}";
/// Connection established message template.
pub const MSG_CONNECTED: &str = "Connected to {}";
/// Disconnection message.
pub const MSG_DISCONNECTED: &str = "Disconnected";
/// Detection in progress placeholder.
pub const MSG_DETECTING: &str = "Detecting...";
/// Data fetching placeholder.
pub const MSG_FETCHING: &str = "Fetching...";
/// No data available placeholder.
pub const MSG_NO_DATA: &str = "---";

// === Cryptographic Defaults ===

/// Default cipher suite for `WireGuard` connections.
pub const DEFAULT_CIPHER: &str = "ChaCha20Poly1305";
