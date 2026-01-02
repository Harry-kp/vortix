//! VPN profile import functionality

use crate::app::{Protocol, VpnProfile};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Import a VPN profile from a file
pub fn import_profile(path: &Path) -> Result<VpnProfile, String> {
    // Check file exists
    if !path.exists() {
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
        _ => return Err(format!("Unsupported file type: .{extension}")),
    };

    // Read and parse the file
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {e}"))?;

    // Extract profile info
    let (name, location) = match protocol {
        Protocol::WireGuard => parse_wireguard_config(&content, path)?,
        Protocol::OpenVPN => parse_openvpn_config(&content, path)?,
    };

    // Copy to profiles directory
    let profiles_dir = get_profiles_dir()?;
    let dest_filename = format!("{name}.{extension}");
    let dest_path = profiles_dir.join(&dest_filename);

    fs::copy(path, &dest_path).map_err(|e| format!("Failed to copy profile: {e}"))?;

    // Secure the file (chmod 600)
    let mut perms = fs::metadata(&dest_path)
        .map_err(|e| format!("Failed to read metadata: {e}"))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&dest_path, perms)
        .map_err(|e| format!("Failed to set permissions: {e}"))?;

    Ok(VpnProfile {
        name,
        protocol,
        location,
        config_path: dest_path,
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
fn derive_location_from_name(name: &str) -> String {
    let name_lower = name.to_lowercase();

    // Check longer/more specific patterns first to avoid false matches
    // e.g., "frankfurt" should match Frankfurt, not "fr" -> France
    let city_patterns = [
        ("frankfurt", "Frankfurt"),
        ("amsterdam", "Amsterdam"),
        ("losangeles", "Los Angeles"),
        ("los-angeles", "Los Angeles"),
        ("newyork", "New York"),
        ("new-york", "New York"),
        ("tokyo", "Tokyo"),
        ("london", "London"),
        ("paris", "Paris"),
    ];

    for (pattern, location) in city_patterns {
        if name_lower.contains(pattern) {
            return location.to_string();
        }
    }

    // Then check country codes (shorter patterns)
    let country_patterns = [
        ("nl", "NL"),
        ("us", "US"),
        ("uk", "GB"),
        ("gb", "GB"),
        ("de", "DE"),
        ("fr", "FR"),
        ("jp", "JP"),
        ("ca", "CA"),
        ("au", "AU"),
        ("sg", "SG"),
        ("ch", "CH"),
        ("la", "Los Angeles"),
    ];

    for (pattern, location) in country_patterns {
        if name_lower.starts_with(pattern) || name_lower.contains(&format!("-{pattern}")) {
            return location.to_string();
        }
    }

    // Default
    "Unknown".to_string()
}

/// Get the profiles directory, creating it if needed
pub fn get_profiles_dir() -> Result<PathBuf, String> {
    crate::utils::get_profiles_dir().map_err(|e| format!("Failed to get profiles directory: {e}"))
}

/// Load all profiles from the profiles directory
pub fn load_profiles() -> Vec<VpnProfile> {
    let Ok(profiles_dir) = get_profiles_dir() else {
        return Vec::new();
    };

    let mut profiles = Vec::new();

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

                        if let Ok((name, location)) = result {
                            // Enforce secure permissions (chmod 600) whenever loaded
                            if let Ok(metadata) = fs::metadata(&path) {
                                let mut perms = metadata.permissions();
                                if perms.mode() & 0o777 != 0o600 {
                                    perms.set_mode(0o600);
                                    let _ = fs::set_permissions(&path, perms);
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
                            });
                        }
                    }
                }
            }
        }
    }

    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_location_us() {
        assert_eq!(derive_location_from_name("us-east-1"), "US");
        assert_eq!(derive_location_from_name("us-west"), "US");
        assert_eq!(derive_location_from_name("vpn-us-01"), "US");
    }

    #[test]
    fn test_derive_location_eu() {
        assert_eq!(derive_location_from_name("nl-01"), "NL");
        assert_eq!(derive_location_from_name("de-berlin"), "DE");
        assert_eq!(derive_location_from_name("uk-server"), "GB");
        assert_eq!(derive_location_from_name("fr-01"), "FR");
    }

    #[test]
    fn test_derive_location_asia() {
        assert_eq!(derive_location_from_name("jp-01"), "JP");
        assert_eq!(derive_location_from_name("sg-01"), "SG");
        assert_eq!(derive_location_from_name("tokyo-server"), "Tokyo");
    }

    #[test]
    fn test_derive_location_unknown() {
        assert_eq!(derive_location_from_name("my-vpn"), "Unknown");
        assert_eq!(derive_location_from_name("server-01"), "Unknown");
    }

    #[test]
    fn test_derive_location_cities() {
        assert_eq!(derive_location_from_name("london-server"), "London");
        assert_eq!(derive_location_from_name("paris-vpn"), "Paris");
        assert_eq!(derive_location_from_name("amsterdam-01"), "Amsterdam");
        assert_eq!(derive_location_from_name("frankfurt-dc"), "Frankfurt");
        assert_eq!(derive_location_from_name("tokyo-primary"), "Tokyo");
    }

    #[test]
    fn test_parse_wireguard_config_basic() {
        let config = r#"
[Interface]
PrivateKey = abc123
Address = 10.0.0.2/32

[Peer]
PublicKey = xyz789
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"#;
        let path = std::path::Path::new("/tmp/us-east.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_ok());
        let (name, _location) = result.unwrap();
        assert_eq!(name, "us-east");
    }

    #[test]
    fn test_parse_wireguard_config_no_endpoint() {
        let config = r#"
[Interface]
PrivateKey = abc123
Address = 10.0.0.2/32

[Peer]
PublicKey = xyz789
AllowedIPs = 0.0.0.0/0
"#;
        let path = std::path::Path::new("/tmp/test.conf");
        let result = parse_wireguard_config(config, path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No Endpoint found"));
    }

    #[test]
    fn test_parse_openvpn_config_basic() {
        let config = r#"
client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
"#;
        let path = std::path::Path::new("/tmp/nl-amsterdam.ovpn");
        let result = parse_openvpn_config(config, path);
        assert!(result.is_ok());
        let (name, _location) = result.unwrap();
        assert_eq!(name, "nl-amsterdam");
    }

    #[test]
    fn test_parse_openvpn_config_no_remote() {
        let config = r#"
client
dev tun
proto udp
"#;
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
