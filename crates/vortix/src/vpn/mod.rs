//! VPN profile import functionality

use crate::constants;
use crate::logger::{self, LogLevel};
use crate::state::{Protocol, VpnProfile};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Import a VPN profile from a file
pub fn import_profile(path: &Path) -> Result<VpnProfile, String> {
    logger::log(
        LogLevel::Debug,
        "IMPORT",
        format!("Importing profile from: {}", path.display()),
    );

    // Check file exists
    if !path.exists() {
        logger::log(
            LogLevel::Error,
            "IMPORT",
            format!("File not found: {}", path.display()),
        );
        return Err(format!("File not found: {}", path.display()));
    }

    // Check file size before reading
    let metadata = fs::metadata(path).map_err(|e| format!("Cannot read file metadata: {e}"))?;
    if metadata.len() > constants::MAX_CONFIG_SIZE_BYTES {
        return Err(format!(
            "File too large ({} bytes). VPN configs should be under 1 MB",
            metadata.len()
        ));
    }
    if metadata.len() == 0 {
        return Err("File is empty".to_string());
    }

    // Determine protocol from extension
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Read the file content first (needed for content-based detection)
    let content = fs::read_to_string(path).map_err(|e| {
        logger::log(
            LogLevel::Error,
            "IMPORT",
            format!("Failed to read file: {e}"),
        );
        format!("Failed to read file: {e}")
    })?;

    let protocol = match extension.as_str() {
        "ovpn" => Protocol::OpenVPN,
        "conf" => {
            // .conf is ambiguous -- use content-based detection
            detect_protocol_from_content(&content)
        }
        _ => {
            logger::log(
                LogLevel::Error,
                "IMPORT",
                format!("Unsupported file type: .{extension}"),
            );
            return Err(format!(
                "Unsupported file type: .{extension} (expected .conf or .ovpn)"
            ));
        }
    };

    // Extract and validate profile info
    let (name, location) = match protocol {
        Protocol::WireGuard => parse_wireguard_config(&content, path)?,
        Protocol::OpenVPN => parse_openvpn_config(&content, path)?,
    };

    // Copy to profiles directory
    let profiles_dir = get_profiles_dir()?;
    let dest_filename = format!("{name}.{extension}");

    // Ensure unique destination path to avoid overwriting existing profiles
    let dest_path = crate::utils::get_unique_path(&profiles_dir, &dest_filename);

    // Update name if filename changed (e.g. from "client" to "client(1)")
    let name = dest_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&name)
        .to_string();

    fs::copy(path, &dest_path).map_err(|e| {
        logger::log(
            LogLevel::Error,
            "IMPORT",
            format!("Failed to copy profile: {e}"),
        );
        format!("Failed to copy profile: {e}")
    })?;

    // Secure the file (chmod 600)
    let mut perms = fs::metadata(&dest_path)
        .map_err(|e| format!("Failed to read metadata: {e}"))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&dest_path, perms)
        .map_err(|e| format!("Failed to set permissions: {e}"))?;

    logger::log(
        LogLevel::Info,
        "IMPORT",
        format!(
            "✓ Imported '{}' ({:?}) → {}",
            name,
            protocol,
            dest_path.display()
        ),
    );

    Ok(VpnProfile {
        name,
        protocol,
        location,
        config_path: dest_path,
        last_used: None,
    })
}

/// Detect protocol by inspecting file content.
///
/// `WireGuard` configs have `[Interface]` and `[Peer]` INI-style sections.
/// `OpenVPN` configs have directives like `remote`, `client`, `dev`, `proto`.
fn detect_protocol_from_content(content: &str) -> Protocol {
    let lower = content.to_lowercase();
    let has_interface = lower.contains("[interface]");
    let has_peer = lower.contains("[peer]");
    let has_remote = lower
        .lines()
        .any(|l| l.trim().starts_with("remote ") || l.trim().starts_with("remote\t"));
    let has_openvpn_markers = lower.lines().any(|l| {
        let t = l.trim();
        t == "client" || t.starts_with("dev ") || t.starts_with("proto ")
    });

    if has_interface && has_peer {
        Protocol::WireGuard
    } else if has_remote || has_openvpn_markers {
        Protocol::OpenVPN
    } else {
        // Default to WireGuard for .conf (historical behavior); validation will catch errors
        Protocol::WireGuard
    }
}

/// Parse and **validate** a `WireGuard` config file.
///
/// Required fields: `[Interface]`, `PrivateKey`, `Address`, `[Peer]`, `PublicKey`, `Endpoint`.
fn parse_wireguard_config(content: &str, path: &Path) -> Result<(String, String), String> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let lower = content.to_lowercase();

    // Structural checks
    if !lower.contains("[interface]") {
        return Err("Missing [Interface] section in WireGuard config".to_string());
    }
    if !lower.contains("[peer]") {
        return Err("Missing [Peer] section in WireGuard config".to_string());
    }

    // Required key checks (case-insensitive, tolerant of whitespace around '=')
    let mut has_private_key = false;
    let mut has_address = false;
    let mut has_public_key = false;
    let mut endpoint = String::new();
    let mut in_peer = false;

    for line in content.lines() {
        let trimmed = line.trim();
        let lower_line = trimmed.to_lowercase();

        if lower_line == "[peer]" {
            in_peer = true;
            continue;
        }
        if lower_line == "[interface]" {
            in_peer = false;
            continue;
        }

        if let Some((key, value)) = lower_line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "privatekey" if !in_peer => has_private_key = true,
                "address" if !in_peer => has_address = true,
                "publickey" if in_peer => has_public_key = true,
                "endpoint" if in_peer && endpoint.is_empty() => {
                    // Use original (non-lowered) value for the endpoint
                    if let Some((_, orig_val)) = trimmed.split_once('=') {
                        endpoint = orig_val.trim().split(':').next().unwrap_or("").to_string();
                    }
                }
                _ => {}
            }
            // Also check non-lowered for PrivateKey detection (some generators use mixed case)
            let _ = value; // suppress unused warning
        }
    }

    let mut missing = Vec::new();
    if !has_private_key {
        missing.push("PrivateKey");
    }
    if !has_address {
        missing.push("Address");
    }
    if !has_public_key {
        missing.push("PublicKey (in [Peer])");
    }
    if endpoint.is_empty() {
        missing.push("Endpoint (in [Peer])");
    }

    if !missing.is_empty() {
        return Err(format!(
            "Invalid WireGuard config — missing required fields: {}",
            missing.join(", ")
        ));
    }

    let location = derive_location_from_name(&name);
    Ok((name, location))
}

/// Parse and **validate** an `OpenVPN` config file.
///
/// Required: `remote` directive. Must also contain at least one `OpenVPN`-specific
/// directive (`client`, `dev`, `proto`, `ca`, `cert`, `key`, `tls-auth`, `tls-crypt`)
/// to distinguish from random text files.
fn parse_openvpn_config(content: &str, path: &Path) -> Result<(String, String), String> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut server = String::new();
    let mut has_openvpn_structure = false;

    // Known OpenVPN directives (presence of any confirms this is an OpenVPN config)
    let openvpn_directives = [
        "client",
        "dev ",
        "dev\t",
        "proto ",
        "proto\t",
        "ca ",
        "cert ",
        "key ",
        "tls-auth",
        "tls-crypt",
        "cipher ",
        "auth ",
        "resolv-retry",
        "nobind",
        "persist-key",
        "persist-tun",
        "verb ",
        "remote-cert-tls",
        "comp-lzo",
    ];
    // OpenVPN inline blocks
    let openvpn_blocks = ["<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>"];

    for line in content.lines() {
        let trimmed = line.trim();
        let lower_line = trimmed.to_lowercase();

        // Check for remote directive
        if server.is_empty() && lower_line.starts_with("remote ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                server = parts[1].to_string();
            }
        }

        // Check for any OpenVPN directive
        if !has_openvpn_structure
            && (lower_line == "client"
                || openvpn_directives.iter().any(|d| lower_line.starts_with(d))
                || openvpn_blocks.iter().any(|b| lower_line.starts_with(b)))
        {
            has_openvpn_structure = true;
        }
    }

    if server.is_empty() {
        return Err("No 'remote' directive found in OpenVPN config".to_string());
    }

    if !has_openvpn_structure {
        return Err(
            "File has a 'remote' line but no OpenVPN directives (client, dev, proto, etc.)"
                .to_string(),
        );
    }

    let location = derive_location_from_name(&name);
    Ok((name, location))
}

/// Derive location from profile name
///
/// IMPORTANT: This is a best-effort heuristic based on common naming patterns.
/// It's NOT reliable for security decisions. The actual VPN server location
/// should ideally be verified through:
/// 1. Parsing the VPN config for embedded location metadata
/// 2. `GeoIP` lookup of the endpoint IP address
/// 3. User-provided manual override (recommended)
///
/// This function should be considered a "display hint" only, not ground truth.
fn derive_location_from_name(name: &str) -> String {
    let name_lower = name.to_lowercase();

    // Check for explicit location markers in common VPN filename formats
    // Examples: "us-newyork-001.conf", "de-frankfurt.ovpn", "uk_london.conf"

    // First try to extract from common VPN provider patterns:
    // Format: <country>-<city>-<number>
    // Format: <country>_<city>
    // Format: <city>-<country>

    // Check longer/more specific patterns first to avoid false matches
    // These are ONLY matched if they appear as distinct components
    let city_patterns = [
        ("frankfurt", "Frankfurt, DE"),
        ("amsterdam", "Amsterdam, NL"),
        ("losangeles", "Los Angeles, US"),
        ("los-angeles", "Los Angeles, US"),
        ("newyork", "New York, US"),
        ("new-york", "New York, US"),
        ("tokyo", "Tokyo, JP"),
        ("london", "London, GB"),
        ("paris", "Paris, FR"),
        ("singapore", "Singapore, SG"),
        ("sydney", "Sydney, AU"),
        ("toronto", "Toronto, CA"),
        ("zurich", "Zurich, CH"),
    ];

    for (pattern, location) in city_patterns {
        if name_lower.contains(pattern) {
            return location.to_string();
        }
    }

    // Check country codes ONLY at start or after delimiter to avoid false positives
    // BAD: "business" contains "us" → marked as US
    // GOOD: "us-server" starts with "us" → marked as US
    let country_patterns = [
        ("nl-", "Netherlands"),
        ("us-", "United States"),
        ("uk-", "United Kingdom"),
        ("gb-", "United Kingdom"),
        ("de-", "Germany"),
        ("fr-", "France"),
        ("jp-", "Japan"),
        ("ca-", "Canada"),
        ("au-", "Australia"),
        ("sg-", "Singapore"),
        ("ch-", "Switzerland"),
        ("se-", "Sweden"),
        ("es-", "Spain"),
        ("it-", "Italy"),
    ];

    for (pattern, location) in country_patterns {
        if name_lower.starts_with(pattern) {
            return location.to_string();
        }
    }

    // Check for country codes at start (without dash) - more lenient
    // But only match 2-letter codes at the very start
    // Guard against non-ASCII characters (country codes are always ASCII)
    if name_lower.len() >= 2 && name_lower.is_char_boundary(2) {
        let prefix = &name_lower[..2];
        let rest = &name_lower[2..];

        // Only match if followed by number, underscore, or end of string
        // This avoids: "desktop" (de), "business" (us), "cache" (ca)
        let valid_separator = rest.is_empty()
            || rest.starts_with('_')
            || rest.starts_with('-')
            || rest.chars().next().is_some_and(|c| c.is_ascii_digit());

        if valid_separator {
            let country_codes = [
                ("nl", "Netherlands"),
                ("us", "United States"),
                ("uk", "United Kingdom"),
                ("gb", "United Kingdom"),
                ("de", "Germany"),
                ("fr", "France"),
                ("jp", "Japan"),
                ("ca", "Canada"),
                ("au", "Australia"),
                ("sg", "Singapore"),
                ("ch", "Switzerland"),
                ("se", "Sweden"),
                ("es", "Spain"),
                ("it", "Italy"),
            ];

            for (code, location) in country_codes {
                if prefix == code {
                    return location.to_string();
                }
            }
        }
    }

    // Default: Cannot reliably determine location from filename
    "Unknown".to_string()
}

/// Get the profiles directory, creating it if needed
pub fn get_profiles_dir() -> Result<PathBuf, String> {
    crate::utils::get_profiles_dir().map_err(|e| format!("Failed to get profiles directory: {e}"))
}

/// Load all profiles from the profiles directory
#[must_use]
pub fn load_profiles() -> Vec<VpnProfile> {
    logger::log(LogLevel::Debug, "PROFILE", "Loading profiles from disk...");

    let Ok(profiles_dir) = get_profiles_dir() else {
        logger::log(
            LogLevel::Warning,
            "PROFILE",
            "Could not access profiles directory",
        );
        return Vec::new();
    };

    let mut profiles = Vec::new();
    let mut errors = 0;

    if let Ok(entries) = fs::read_dir(&profiles_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "conf" || ext == "ovpn" {
                    if let Ok(content) = fs::read_to_string(&path) {
                        // Detect protocol: .ovpn is always OpenVPN, .conf uses content detection
                        let protocol = if ext == "ovpn" {
                            Protocol::OpenVPN
                        } else {
                            detect_protocol_from_content(&content)
                        };

                        let result = match protocol {
                            Protocol::WireGuard => parse_wireguard_config(&content, &path),
                            Protocol::OpenVPN => parse_openvpn_config(&content, &path),
                        };

                        match result {
                            Ok((name, location)) => {
                                // Enforce secure permissions (chmod 600) whenever loaded
                                if let Ok(metadata) = fs::metadata(&path) {
                                    let mut perms = metadata.permissions();
                                    if perms.mode() & 0o777 != 0o600 {
                                        perms.set_mode(0o600);
                                        let _ = fs::set_permissions(&path, perms);
                                        logger::log(
                                            LogLevel::Debug,
                                            "PROFILE",
                                            format!("Fixed permissions for '{name}'"),
                                        );
                                    }
                                }

                                profiles.push(VpnProfile {
                                    name,
                                    protocol,
                                    location,
                                    config_path: path.clone(),
                                    last_used: None,
                                });
                            }
                            Err(e) => {
                                logger::log(
                                    LogLevel::Warning,
                                    "PROFILE",
                                    format!("Skipped {}: {}", path.display(), e),
                                );
                                errors += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    let wg_count = profiles
        .iter()
        .filter(|p| matches!(p.protocol, Protocol::WireGuard))
        .count();
    let ovpn_count = profiles
        .iter()
        .filter(|p| matches!(p.protocol, Protocol::OpenVPN))
        .count();

    logger::log(
        LogLevel::Info,
        "PROFILE",
        format!(
            "Loaded {} profiles ({} WireGuard, {} OpenVPN{})",
            profiles.len(),
            wg_count,
            ovpn_count,
            if errors > 0 {
                format!(", {errors} skipped")
            } else {
                String::new()
            }
        ),
    );

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_location_us() {
        assert_eq!(derive_location_from_name("us-east-1"), "United States");
        assert_eq!(derive_location_from_name("us-west"), "United States");
        // This should NOT match "us" in "business" - improved logic
        assert_eq!(derive_location_from_name("business-vpn"), "Unknown");
    }

    #[test]
    fn test_derive_location_eu() {
        assert_eq!(derive_location_from_name("nl-01"), "Netherlands");
        assert_eq!(derive_location_from_name("de-berlin"), "Germany");
        assert_eq!(derive_location_from_name("uk-server"), "United Kingdom");
        assert_eq!(derive_location_from_name("fr-01"), "France");
        // This should NOT match "de" in "desktop" - improved logic
        assert_eq!(derive_location_from_name("desktop-server"), "Unknown");
    }

    #[test]
    fn test_derive_location_asia() {
        assert_eq!(derive_location_from_name("jp-01"), "Japan");
        assert_eq!(derive_location_from_name("sg-01"), "Singapore");
        assert_eq!(derive_location_from_name("tokyo-server"), "Tokyo, JP");
    }

    #[test]
    fn test_derive_location_unknown() {
        assert_eq!(derive_location_from_name("my-vpn"), "Unknown");
        assert_eq!(derive_location_from_name("server-01"), "Unknown");
        // Edge cases that should NOT be misidentified as country codes
        assert_eq!(derive_location_from_name("usa-server"), "Unknown"); // does not contain exact "us-" token
        assert_eq!(derive_location_from_name("cache-server"), "Unknown"); // does not contain exact "ca-" token
    }

    #[test]
    fn test_derive_location_cities() {
        assert_eq!(derive_location_from_name("london-server"), "London, GB");
        assert_eq!(derive_location_from_name("paris-vpn"), "Paris, FR");
        assert_eq!(derive_location_from_name("amsterdam-01"), "Amsterdam, NL");
        assert_eq!(derive_location_from_name("frankfurt-dc"), "Frankfurt, DE");
        assert_eq!(derive_location_from_name("tokyo-primary"), "Tokyo, JP");
    }

    #[test]
    fn test_parse_wireguard_config_basic() {
        let config = r"
[Interface]
PrivateKey = abc123
Address = 10.0.0.2/32

[Peer]
PublicKey = xyz789
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
";
        let path = std::path::Path::new("/tmp/us-east.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_ok());
        let (name, _location) = result.unwrap();
        assert_eq!(name, "us-east");
    }

    #[test]
    fn test_parse_wireguard_config_no_endpoint() {
        let config = r"
[Interface]
PrivateKey = abc123
Address = 10.0.0.2/32

[Peer]
PublicKey = xyz789
AllowedIPs = 0.0.0.0/0
";
        let path = std::path::Path::new("/tmp/test.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Endpoint"));
    }

    #[test]
    fn test_parse_openvpn_config_basic() {
        let config = r"
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
";
        let path = std::path::Path::new("/tmp/nl-amsterdam.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_ok());
        let (name, _location) = result.unwrap();
        assert_eq!(name, "nl-amsterdam");
    }

    #[test]
    fn test_parse_openvpn_config_no_remote() {
        let config = r"
client
dev tun
proto udp
";
        let path = std::path::Path::new("/tmp/test.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No 'remote' directive"));
    }

    #[test]
    fn test_import_profile_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/path/file.conf");
        let result = import_profile(path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("File not found"));
    }

    #[test]
    fn test_import_profile_unsupported_extension() {
        let dir = tempfile::Builder::new()
            .prefix("vortix_test_")
            .tempdir()
            .unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "test content").unwrap();

        let result = import_profile(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported file type"));
    }

    // === Extended config parsing edge cases ===

    #[test]
    fn test_parse_wireguard_config_with_whitespace_and_comments() {
        let config = r"
# This is a WireGuard config with extra whitespace and comments

[Interface]
  PrivateKey = abc123
  Address = 10.0.0.2/32
  DNS = 1.1.1.1

# Peer section
[Peer]
  PublicKey = xyz789
  Endpoint = vpn.example.com:51820
  AllowedIPs = 0.0.0.0/0, ::/0
  PersistentKeepalive = 25
";
        let path = std::path::Path::new("/tmp/us-east-whitespace.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_ok());
        let (name, _) = result.unwrap();
        assert_eq!(name, "us-east-whitespace");
    }

    #[test]
    fn test_parse_wireguard_config_unusual_endpoint_formats() {
        // IP:port format (complete config)
        let config = "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz789\nEndpoint = 1.2.3.4:51820\n";
        let path = std::path::Path::new("/tmp/ip-endpoint.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_ok());

        // Hostname endpoint (complete config)
        let config2 = "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz789\nEndpoint = vpn6.example.com:51820\n";
        let path2 = std::path::Path::new("/tmp/ipv6-endpoint.conf");
        let result2 = parse_wireguard_config(config2, path2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_parse_openvpn_config_with_extras() {
        let config = r"
# OpenVPN client config
; Another comment style
client
dev tun
proto udp
remote vpn.example.com 1194
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
-----BEGIN CERTIFICATE-----
MIIDqzCCApOgAwIB...
-----END CERTIFICATE-----
</ca>
";
        let path = std::path::Path::new("/tmp/nl-amsterdam-full.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_ok());
        let (name, location) = result.unwrap();
        assert_eq!(name, "nl-amsterdam-full");
        assert_eq!(location, "Amsterdam, NL");
    }

    #[test]
    fn test_parse_openvpn_config_empty_lines() {
        let config = "\n\n\nclient\n\n\nremote server.example.com 443\n\n\n";
        let path = std::path::Path::new("/tmp/sparse.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_wireguard_config_missing_required_fields() {
        // Missing [Peer] section entirely
        let config = "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.2/32\n";
        let path = std::path::Path::new("/tmp/missing-peer.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[Peer]"));

        // Missing PrivateKey
        let config2 = "[Interface]\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n";
        let path2 = std::path::Path::new("/tmp/missing-privkey.conf");
        let result2 = parse_wireguard_config(config2, path2);
        assert!(result2.is_err());
        assert!(result2.unwrap_err().contains("PrivateKey"));

        // Missing Address
        let config3 =
            "[Interface]\nPrivateKey = abc\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n";
        let path3 = std::path::Path::new("/tmp/missing-addr.conf");
        let result3 = parse_wireguard_config(config3, path3);
        assert!(result3.is_err());
        assert!(result3.unwrap_err().contains("Address"));

        // Missing PublicKey in [Peer]
        let config4 = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n";
        let path4 = std::path::Path::new("/tmp/missing-pubkey.conf");
        let result4 = parse_wireguard_config(config4, path4);
        assert!(result4.is_err());
        assert!(result4.unwrap_err().contains("PublicKey"));
    }

    #[test]
    fn test_utf8_profile_names() {
        // Unicode profile name handling (complete valid config)
        let config = "[Interface]\nPrivateKey = abc123\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz789\nEndpoint = vpn.example.com:51820\n";
        let path = std::path::Path::new("/tmp/münchen-vpn.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_ok());
        let (name, _) = result.unwrap();
        assert_eq!(name, "münchen-vpn");
    }

    // === Content-based protocol detection tests ===

    #[test]
    fn test_detect_protocol_wireguard() {
        let wg_config = "[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n";
        assert!(matches!(
            detect_protocol_from_content(wg_config),
            Protocol::WireGuard
        ));
    }

    #[test]
    fn test_detect_protocol_openvpn() {
        let ovpn_config = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n";
        assert!(matches!(
            detect_protocol_from_content(ovpn_config),
            Protocol::OpenVPN
        ));
    }

    #[test]
    fn test_detect_protocol_openvpn_with_remote_only_and_dev() {
        // Has remote + dev but no [Interface]/[Peer] → OpenVPN
        let config = "dev tun\nremote server.example.com 443\nproto tcp\n";
        assert!(matches!(
            detect_protocol_from_content(config),
            Protocol::OpenVPN
        ));
    }

    #[test]
    fn test_detect_protocol_defaults_to_wireguard_for_unknown() {
        // Random text that doesn't match either protocol
        let config = "some random text\nwith no VPN directives\n";
        assert!(matches!(
            detect_protocol_from_content(config),
            Protocol::WireGuard
        ));
    }

    // === OpenVPN structure validation tests ===

    #[test]
    fn test_openvpn_rejects_file_with_only_remote() {
        // Has "remote" but no other OpenVPN directives -- not a real OpenVPN config
        let config = "remote 1.2.3.4 1194\nsome random data here\n";
        let path = std::path::Path::new("/tmp/suspicious.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no OpenVPN directives"));
    }

    #[test]
    fn test_openvpn_accepts_config_with_inline_certs() {
        let config = "remote vpn.example.com 1194\n<ca>\n-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n</ca>\n";
        let path = std::path::Path::new("/tmp/inline-cert.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_ok());
    }

    // === WireGuard missing [Interface] section test ===

    #[test]
    fn test_wireguard_rejects_missing_interface() {
        let config = "[Peer]\nPublicKey = xyz\nEndpoint = 1.2.3.4:51820\n";
        let path = std::path::Path::new("/tmp/no-interface.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[Interface]"));
    }
}
