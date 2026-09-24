//! Pure types, capability ports, and runtime services shared by the CLI and TUI.

#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]

pub mod cidr;
pub mod cidr_subtract;
pub mod dns_policy;
pub mod downloader;
pub mod engine;
pub mod icmp;
pub mod ids;
pub mod importer;
pub mod journal;
pub mod killswitch;
pub mod managed_wireguard;
pub mod openvpn_routes;
pub mod ports;
pub mod profile;
pub mod real_ip_cache;
pub mod scanner;
pub mod secret;
pub mod secret_file;
pub mod standard_tunnel_ownership;
pub mod state;
pub mod telemetry;
pub mod telemetry_http;

pub use cidr::{claims_default_route_v6, Cidr};
pub use cidr_subtract::cidr_subtract;
pub use scanner::{get_active_profiles, ActiveSession};
pub use telemetry::{spawn_telemetry_worker, TelemetryUpdate};
