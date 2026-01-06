//! URL Downloader logic for profile imports.
//!
//! Uses curl command for HTTP requests to avoid heavy dependencies.

use crate::constants;
use crate::logger::{self, LogLevel};
use crate::utils;
use std::path::PathBuf;
use std::process::Command;

/// Downloads a VPN profile from a given URL and saves it to the profiles directory.
///
/// # Arguments
///
/// * `url` - The direct URL to download the config from.
///
/// # Returns
///
/// The `PathBuf` of the saved file, or an Error string.
#[allow(clippy::too_many_lines)]
pub fn download_profile(url: &str) -> Result<PathBuf, String> {
    logger::log(
        LogLevel::Info,
        "DOWNLOAD",
        format!("Fetching profile from URL: {url}"),
    );

    // Extract filename from URL path
    let filename = extract_filename_from_url(url);
    logger::log(
        LogLevel::Debug,
        "DOWNLOAD",
        format!("Extracted filename: {filename}"),
    );

    // Create target path in temp directory
    let profiles_dir = std::env::temp_dir();
    let target_path = utils::get_unique_path(&profiles_dir, &filename);

    // Use curl to download directly to file
    // -f: Fail silently on HTTP errors (returns exit code)
    // -L: Follow redirects
    // -s: Silent mode
    // -S: Show errors even in silent mode
    // --max-time: Timeout
    // -o: Output file
    let output = Command::new("curl")
        .args([
            "-f",
            "-L",
            "-s",
            "-S",
            "--max-time",
            &constants::HTTP_TIMEOUT_SECS.to_string(),
            "-A",
            &format!("{}/{}", constants::APP_NAME, constants::APP_VERSION),
            "-o",
            target_path.to_str().unwrap_or(""),
            url,
        ])
        .output()
        .map_err(|e| {
            logger::log(
                LogLevel::Error,
                "DOWNLOAD",
                format!("Failed to execute curl: {e}"),
            );
            format!("{}: {e}", constants::ERR_HTTP_CLIENT_BUILD_FAILED)
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        logger::log(
            LogLevel::Error,
            "DOWNLOAD",
            format!("curl failed: {stderr}"),
        );

        // Clean up partial download if it exists
        if target_path.exists() {
            let _ = std::fs::remove_file(&target_path);
        }

        // Parse curl error for user-friendly message
        if stderr.contains("Could not resolve host") {
            return Err(format!(
                "{}: Could not resolve host",
                constants::ERR_NETWORK_REQUEST_FAILED
            ));
        } else if stderr.contains("Connection refused") || stderr.contains("Connection timed out") {
            return Err(format!(
                "{}: Connection failed",
                constants::ERR_NETWORK_REQUEST_FAILED
            ));
        } else if stderr.contains("The requested URL returned error") {
            return Err(format!(
                "{}: {}",
                constants::ERR_SERVER_ERROR,
                stderr.trim()
            ));
        }
        return Err(format!(
            "{}: {}",
            constants::ERR_NETWORK_REQUEST_FAILED,
            stderr.trim()
        ));
    }

    // Verify the downloaded file exists and has content
    let metadata = std::fs::metadata(&target_path).map_err(|e| {
        logger::log(
            LogLevel::Error,
            "DOWNLOAD",
            format!("Failed to read downloaded file: {e}"),
        );
        format!("Failed to verify download: {e}")
    })?;

    if metadata.len() == 0 {
        logger::log(LogLevel::Error, "DOWNLOAD", "Downloaded file is empty");
        let _ = std::fs::remove_file(&target_path);
        return Err(constants::ERR_EMPTY_CONTENT.to_string());
    }

    // Check if we accidentally downloaded HTML (common with GitHub web links)
    let content_preview = std::fs::read_to_string(&target_path)
        .map(|s| s.chars().take(100).collect::<String>())
        .unwrap_or_default();

    if content_preview
        .trim_start()
        .to_lowercase()
        .starts_with("<!doctype")
        || content_preview
            .trim_start()
            .to_lowercase()
            .starts_with("<html")
    {
        logger::log(
            LogLevel::Error,
            "DOWNLOAD",
            "Received HTML instead of config file (use raw URL)",
        );
        let _ = std::fs::remove_file(&target_path);
        return Err(constants::ERR_HTML_CONTENT.to_string());
    }

    logger::log(
        LogLevel::Info,
        "DOWNLOAD",
        format!(
            "✓ Downloaded {} ({} bytes) → {}",
            filename,
            metadata.len(),
            target_path.display()
        ),
    );

    Ok(target_path)
}

/// Extract filename from URL path
///
/// # Limitations
///
/// If no explicit `.conf` or `.ovpn` extension is found in the URL path,
/// this function uses a heuristic: if "ovpn" appears anywhere in the URL,
/// it defaults to `.ovpn`, otherwise `.conf`. This may incorrectly classify
/// URLs like `https://example.com/openvpn/download` as needing `.ovpn` when
/// the actual content might be `WireGuard`.
fn extract_filename_from_url(url: &str) -> String {
    // Try to extract filename from URL path
    // e.g., "https://example.com/configs/us-east.conf" -> "us-east.conf"

    // Remove query string and fragment
    let url_path = url.split('?').next().unwrap_or(url);
    let url_path = url_path.split('#').next().unwrap_or(url_path);

    // Get the last path segment
    if let Some(last_segment) = url_path.rsplit('/').next() {
        if !last_segment.is_empty()
            && (last_segment.ends_with(constants::EXT_OVPN)
                || last_segment.ends_with(constants::EXT_CONF))
        {
            return last_segment.to_string();
        }
    }

    // Fallback: determine extension from URL content
    let default_ext = if url.contains(constants::EXT_OVPN) {
        constants::EXT_OVPN
    } else {
        constants::EXT_CONF
    };

    format!("{}.{}", constants::DEFAULT_IMPORTED_FILENAME, default_ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_filename_conf() {
        assert_eq!(
            extract_filename_from_url("https://example.com/configs/us-east.conf"),
            "us-east.conf"
        );
    }

    #[test]
    fn test_extract_filename_ovpn() {
        assert_eq!(
            extract_filename_from_url("https://vpn.provider.com/nl-amsterdam.ovpn"),
            "nl-amsterdam.ovpn"
        );
    }

    #[test]
    fn test_extract_filename_with_query() {
        assert_eq!(
            extract_filename_from_url("https://example.com/test.conf?token=abc123"),
            "test.conf"
        );
    }

    #[test]
    fn test_extract_filename_with_fragment() {
        assert_eq!(
            extract_filename_from_url("https://example.com/config.ovpn#section"),
            "config.ovpn"
        );
    }

    #[test]
    fn test_extract_filename_github_raw() {
        assert_eq!(
            extract_filename_from_url(
                "https://raw.githubusercontent.com/user/repo/main/configs/server.conf"
            ),
            "server.conf"
        );
    }

    #[test]
    fn test_extract_filename_no_extension() {
        // Should default to .conf
        let result = extract_filename_from_url("https://example.com/api/getconfig");
        assert!(result.ends_with(".conf"));
    }

    #[test]
    fn test_extract_filename_ovpn_in_url() {
        // Should use .ovpn if mentioned in URL
        let result = extract_filename_from_url("https://example.com/openvpn/download");
        assert!(result.ends_with(".conf") || result.contains("ovpn"));
    }
}
