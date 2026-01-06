//! VPN profile import functionality

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

    // Determine protocol from extension
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let protocol = match extension.as_str() {
        "conf" => Protocol::WireGuard,
        "ovpn" => Protocol::OpenVPN,
        _ => {
            logger::log(
                LogLevel::Error,
                "IMPORT",
                format!("Unsupported file type: .{extension}"),
            );
            return Err(format!("Unsupported file type: .{extension}"));
        }
    };

    // Read and parse the file
    let content = fs::read_to_string(path).map_err(|e| {
        logger::log(
            LogLevel::Error,
            "IMPORT",
            format!("Failed to read file: {e}"),
        );
        format!("Failed to read file: {e}")
    })?;

    // Extract profile info
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

/// Parse `WireGuard` config file
fn parse_wireguard_config(content: &str, path: &Path) -> Result<(String, String), String> {
    // Extract name from filename
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Look for Endpoint in [Peer] section
    let mut server = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("endpoint") {
            if let Some(value) = line.split('=').nth(1) {
                // Format: Endpoint = server:port
                server = value.trim().split(':').next().unwrap_or("").to_string();
                break;
            }
        }
    }

    if server.is_empty() {
        return Err("No Endpoint found in WireGuard config".to_string());
    }

    // Try to derive location from name (common patterns: us-east, nl-01, tokyo, etc.)
    let location = derive_location_from_name(&name);

    Ok((name, location))
}

/// Parse `OpenVPN` config file
fn parse_openvpn_config(content: &str, path: &Path) -> Result<(String, String), String> {
    // Extract name from filename
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Look for 'remote' directive
    let mut server = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("remote ") {
            // Format: remote server port
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                server = parts[1].to_string();
                break;
            }
        }
    }

    if server.is_empty() {
        return Err("No 'remote' directive found in OpenVPN config".to_string());
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
    if name_lower.len() >= 2 {
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
                        let result = match ext {
                            "conf" => parse_wireguard_config(&content, &path),
                            "ovpn" => parse_openvpn_config(&content, &path),
                            _ => continue,
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

                                let protocol = if ext == "conf" {
                                    Protocol::WireGuard
                                } else {
                                    Protocol::OpenVPN
                                };

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
        assert!(result.unwrap_err().contains("No Endpoint found"));
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
        // Create a temp file with wrong extension
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join("test.txt");
        std::fs::write(&path, "test content").unwrap();

        let result = import_profile(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported file type"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }
}
