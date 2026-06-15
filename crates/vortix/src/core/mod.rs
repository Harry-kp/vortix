//! Core modules for VPN detection and telemetry.
//!
//! This module contains production-ready background workers:
//! - `scanner`: Detects active VPN connections on the system
//! - `telemetry`: Collects network telemetry (IP, latency, ISP, etc.)
//! - `killswitch`: macOS pf firewall control for traffic blocking

#![allow(unused_imports)]

pub mod dns_leak;
pub mod downloader;
pub mod icmp;
pub mod importer;
pub mod killswitch;
pub mod network_monitor;
pub mod real_ip_cache;
pub mod scanner;
pub mod telemetry;
pub mod telemetry_http;

// Re-export commonly used items
pub use scanner::{get_active_profiles, ActiveSession};
pub use telemetry::{spawn_telemetry_worker, TelemetryUpdate};
