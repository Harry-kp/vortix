//! Application-wide constants and configuration values.
//!
//! This module defines all static configuration values used throughout Vortix,
//! including timing intervals, API endpoints, file paths, and UI messages.

// === Application Metadata ===

/// Application name and title (from Cargo.toml).
pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
/// Current application version (from Cargo.toml).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// === Timing Defaults ===
// These are the compiled-in defaults. Users can override them via config.toml.
// AppConfig::default() references these so there is exactly one source of truth.

/// Default UI refresh rate in milliseconds.
pub const DEFAULT_TICK_RATE: u64 = 1000;
/// Default interval between telemetry API calls (seconds).
pub const DEFAULT_TELEMETRY_POLL_RATE: u64 = 30;
/// Default timeout for HTTP API calls (seconds).
pub const DEFAULT_API_TIMEOUT: u64 = 5;
/// Default timeout for ping commands (seconds).
pub const DEFAULT_PING_TIMEOUT: u64 = 2;
/// Default maximum seconds to wait for `OpenVPN` log confirmation.
pub const DEFAULT_CONNECT_TIMEOUT: u64 = 20;
/// Maximum seconds to wait for a local system command (`ps`, `netstat`, etc.)
/// before killing it. Prevents the TUI from freezing when commands hang.
pub const CMD_TIMEOUT_SECS: u64 = 3;

// === Telemetry API Endpoint Defaults ===
// Same principle: single source of truth, overridable via config.toml.

/// Default primary API endpoint for IP address and ISP lookup.
pub const DEFAULT_IP_API_PRIMARY: &str = "https://ipinfo.io/json";
/// Default fallback API 1: ipify.org (IP only, very reliable).
pub const DEFAULT_IP_API_FALLBACK_1: &str = "https://api.ipify.org";
/// Default fallback API 2: icanhazip.com (IP only).
pub const DEFAULT_IP_API_FALLBACK_2: &str = "https://icanhazip.com";
/// Default fallback API 3: ifconfig.me (IP only).
pub const DEFAULT_IP_API_FALLBACK_3: &str = "https://ifconfig.me/ip";

/// Default IPv6 leak detection endpoints (any success = leak).
pub const DEFAULT_IPV6_CHECK_APIS: [&str; 3] = [
    "https://ipv6.icanhazip.com",
    "https://v6.ident.me",
    "https://api6.ipify.org",
];

/// Default ping targets for latency measurement (tried in order).
pub const DEFAULT_PING_TARGETS: [&str; 4] = [
    "1.1.1.1",        // Cloudflare
    "8.8.8.8",        // Google
    "9.9.9.9",        // Quad9
    "208.67.222.222", // OpenDNS
];

// === Path Configuration ===

/// Name of the profiles subdirectory.
pub const PROFILES_DIR_NAME: &str = "profiles";
/// Name of the logs subdirectory.
pub const LOGS_DIR_NAME: &str = "logs";
/// Name of the profile metadata file.
pub const METADATA_FILE_NAME: &str = "metadata.json";
/// Kill switch state persistence filename.
pub const KILLSWITCH_STATE_FILE: &str = "killswitch.state";

// === Platform-Specific Paths ===

/// macOS pf configuration file path (temp file for kill switch rules).
#[cfg(target_os = "macos")]
pub const PF_CONF_PATH: &str = "/tmp/vortix_killswitch.conf";
/// macOS `WireGuard` runtime directory.
#[cfg(target_os = "macos")]
pub const WIREGUARD_RUN_DIR: &str = "/var/run/wireguard";
/// Linux network device statistics pseudo-file.
#[cfg(target_os = "linux")]
pub const PROC_NET_DEV_PATH: &str = "/proc/net/dev";
/// System DNS resolver configuration file (both platforms).
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
/// Linux iptables custom chain name for kill switch.
#[cfg(target_os = "linux")]
pub const IPTABLES_CHAIN_NAME: &str = "VORTIX_KILLSWITCH";
/// Linux nftables table name for kill switch.
#[cfg(target_os = "linux")]
pub const NFT_TABLE_NAME: &str = "vortix_killswitch";

// === Telemetry Internal Constants ===
// These are internal tuning values not exposed to user configuration.

/// Timeout for file downloads in seconds.
pub const HTTP_TIMEOUT_SECS: u64 = 10;
/// Delay between retry attempts in milliseconds.
pub const RETRY_DELAY_MS: u64 = 500;
/// Number of retry attempts per API/target.
pub const RETRY_ATTEMPTS: u8 = 2;

// === UI Messages ===

/// Backend initialization message.
pub const MSG_BACKEND_INIT: &str = "IO: Initializing VPN backend...";
/// Detection in progress placeholder.
pub const MSG_DETECTING: &str = "Detecting...";
/// Data fetching placeholder.
pub const MSG_FETCHING: &str = "Fetching...";
/// No data available placeholder.
pub const MSG_NO_DATA: &str = "---";

// === Platform Defaults ===

/// Default VPN interface when none is known.
#[cfg(target_os = "macos")]
pub const DEFAULT_VPN_INTERFACE: &str = "utun0";
#[cfg(target_os = "linux")]
pub const DEFAULT_VPN_INTERFACE: &str = "wg0";

/// Emergency instructions for the user if the kill switch cannot be disabled normally.
#[cfg(target_os = "macos")]
pub const KILLSWITCH_EMERGENCY_MSG: &str = "You may need to run: sudo pfctl -F all";
#[cfg(target_os = "linux")]
pub const KILLSWITCH_EMERGENCY_MSG: &str =
    "You may need to run: sudo iptables -F VORTIX_KILLSWITCH && sudo iptables -X VORTIX_KILLSWITCH (or: sudo nft delete table inet vortix_killswitch)";

// === OpenVPN Runtime Configuration ===

/// Subdirectory under the Vortix config dir for `OpenVPN` runtime files (pid, log).
pub const OPENVPN_RUN_DIR: &str = "run";
/// `OpenVPN` log line indicating successful tunnel establishment.
pub const OVPN_LOG_SUCCESS: &str = "Initialization Sequence Completed";
/// `OpenVPN` log patterns indicating definitive failure.
pub const OVPN_LOG_ERRORS: &[&str] = &[
    "AUTH_FAILED",
    "TLS Error",
    "TLS handshake failed",
    "FATAL",
    "Cannot open TUN/TAP",
    "ERROR:",
    "Exiting due to fatal error",
];
/// Polling interval for `OpenVPN` log file (milliseconds).
pub const OVPN_LOG_POLL_MS: u64 = 500;
/// Subdirectory under the Vortix config dir for `OpenVPN` saved credentials.
pub const OPENVPN_AUTH_DIR: &str = "auth";
/// `OpenVPN` config directive that triggers interactive auth prompts.
pub const OVPN_AUTH_USER_PASS: &str = "auth-user-pass";

// === Auth UI Labels ===

/// Title for the authentication overlay (connect flow).
pub const TITLE_AUTH_PROMPT: &str = " VPN Authentication ";
/// Title for the authentication overlay (manage/edit flow).
pub const TITLE_AUTH_MANAGE: &str = " Edit Auth Credentials ";
/// Footer keybindings for the auth overlay (connect flow).
pub const TITLE_AUTH_FOOTER: &str = " [Tab] Switch  [Enter] Connect  [Esc] Cancel ";
/// Footer keybindings for the auth overlay (manage/edit flow).
pub const TITLE_AUTH_MANAGE_FOOTER: &str = " [Tab] Switch  [Enter] Save  [Esc] Cancel ";

// === Import & Download Configuration ===

/// Maximum config file size (1 MB). Anything larger is almost certainly not a VPN config.
pub const MAX_CONFIG_SIZE_BYTES: u64 = 1_024 * 1_024;

/// Default filename for downloaded profiles if none can be determined.
pub const DEFAULT_IMPORTED_FILENAME: &str = "imported_profile.conf";

// === UI Labels & Titles ===

pub const TITLE_IMPORT_PROFILE: &str = " Import VPN Profile ";
pub const TITLE_IMPORT_FOOTER: &str = " [Enter] Import  [Esc] Cancel ";
pub const PROMPT_IMPORT_PATH: &str = "Enter path to file, directory, or URL:";
pub const HINT_IMPORT_BULK: &str = "💡 Tip: Enter a directory to bulk import all profiles";
pub const LABEL_SUPPORTED_FORMATS: &str = "Supported formats:";
pub const EXT_CONF: &str = ".conf";
pub const EXT_OVPN: &str = ".ovpn";
pub const PROTO_WIREGUARD: &str = "WireGuard";
pub const PROTO_OPENVPN: &str = "OpenVPN";

// === Messages: General (Toast/Logs) ===

pub const MSG_DOWNLOADING: &str = "Downloading profile...";
pub const MSG_DOWNLOAD_FAILED: &str = "Download failed: ";
pub const MSG_IMPORT_SUCCESS: &str = "Imported: ";
pub const MSG_IMPORT_ERROR: &str = "Error: ";
pub const MSG_NO_FILES_FOUND: &str = "No .conf or .ovpn files found";
pub const MSG_BATCH_IMPORTED: &str = "Imported ";
pub const MSG_BATCH_IMPORTED_SUFFIX: &str = " profile(s)";

// === Messages: CLI Output ===

pub const CLI_MSG_DOWNLOADING: &str = "Downloading profile from URL...";
pub const CLI_MSG_IMPORT_SUCCESS: &str = "Imported profile: ";
pub const CLI_MSG_IMPORT_DETAILS_PROTO: &str = "   Protocol: ";
pub const CLI_MSG_IMPORT_DETAILS_LOC: &str = "   Location: ";
pub const CLI_MSG_IMPORT_DETAILS_PATH: &str = "   Saved to: ";
pub const CLI_MSG_IMPORT_FAILED: &str = "Import failed: ";
pub const CLI_MSG_SUMMARY_HEADER: &str = "\nImport Summary:";
pub const CLI_MSG_SUMMARY_IMPORTED: &str = "   Imported: ";
pub const CLI_MSG_SUMMARY_FAILED: &str = "   Failed: ";
pub const CLI_MSG_NO_FILES: &str = "\nNo .conf or .ovpn files found in directory";
pub const CLI_MSG_DIR_ERROR: &str = "Error reading directory: ";
pub const CLI_MSG_ERROR: &str = "Error: ";

pub const CLI_MSG_UPDATE_START: &str = "🔄 Updating vortix...\n";
pub const CLI_MSG_UPDATE_SUCCESS: &str = "Successfully updated vortix!";
pub const CLI_MSG_UPDATE_CHECK: &str = "   Run 'vortix --version' to see the new version.";
pub const CLI_MSG_UPDATE_FAIL_MANUAL: &str = "\nUpdate failed. Please try manually:";
pub const CLI_MSG_UPDATE_CMD: &str = "   cargo install vortix --force";
pub const CLI_MSG_UPDATE_FAIL_CARGO: &str = "Failed to run cargo: ";
pub const CLI_MSG_UPDATE_PATH_HINT: &str = "   Make sure cargo is installed and in your PATH.";

// === Error Messages ===

pub const ERR_HTML_CONTENT: &str =
    "URL returned HTML content. Did you mean to use the 'raw' version of the link?";
pub const ERR_EMPTY_CONTENT: &str = "Downloaded content is empty";
pub const ERR_SERVER_ERROR: &str = "Server returned error: ";
pub const ERR_HTTP_CLIENT_BUILD_FAILED: &str = "Failed to build HTTP client";
pub const ERR_NETWORK_REQUEST_FAILED: &str = "Network request failed";
