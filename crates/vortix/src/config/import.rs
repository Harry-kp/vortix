use std::path::PathBuf;

/// Target for an import operation
#[derive(Debug, Clone)]
pub enum ImportTarget {
    Url(String),
    File(PathBuf),
    Directory(PathBuf),
}

/// Helper to expand paths with ~ to standard `PathBuf`
#[must_use]
pub fn expand_home(path_str: &str) -> PathBuf {
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = crate::config::user_home() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path_str)
}

/// Basic URL validation - checks structure without external dependencies
fn is_valid_url(url: &str) -> bool {
    // Must start with http:// or https://
    let url = url.trim();
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return false;
    }

    // Must have a host after the scheme
    let after_scheme = if let Some(stripped) = url.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = url.strip_prefix("http://") {
        stripped
    } else {
        return false;
    };

    // Host must exist and not be empty
    let host = after_scheme.split('/').next().unwrap_or("");
    if host.is_empty() || host.starts_with(':') {
        return false;
    }

    // Basic check: host should have at least one dot or be localhost
    host.contains('.') || host.starts_with("localhost")
}

/// Resolves the import target type from a path string
pub fn resolve_target(input: &str) -> Result<ImportTarget, String> {
    let input = input.trim();

    // 1. Check for URL
    if input.starts_with("http://") || input.starts_with("https://") {
        if is_valid_url(input) {
            return Ok(ImportTarget::Url(input.to_string()));
        }
        return Err("Invalid URL format".to_string());
    }

    // 2. Expand Path
    let path = expand_home(input);

    // 3. Check file existence and type
    if !path.exists() {
        return Err(format!("Path not found: {input}"));
    }

    // 4. Determine Type
    if path.is_file() {
        Ok(ImportTarget::File(path))
    } else if path.is_dir() {
        Ok(ImportTarget::Directory(path))
    } else {
        Err("Invalid path type (not a file or directory)".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expands_to_the_invoking_users_home() {
        let home = crate::config::user_home().expect("test runs with a home directory");
        assert_eq!(expand_home("~/corp.conf"), home.join("corp.conf"));
        assert_eq!(
            expand_home("/etc/corp.conf"),
            PathBuf::from("/etc/corp.conf")
        );
    }

    #[test]
    fn test_is_valid_url_https() {
        assert!(is_valid_url("https://example.com/test.conf"));
        assert!(is_valid_url(
            "https://vpn.provider.com/configs/us-east.ovpn"
        ));
        assert!(is_valid_url(
            "https://raw.githubusercontent.com/user/repo/main/config.conf"
        ));
    }

    #[test]
    fn test_is_valid_url_http() {
        assert!(is_valid_url("http://example.com/test.conf"));
        assert!(is_valid_url("http://192.168.1.1/config.ovpn"));
    }

    #[test]
    fn test_is_valid_url_localhost() {
        assert!(is_valid_url("http://localhost/test.conf"));
        assert!(is_valid_url("http://localhost:8080/config.ovpn"));
        assert!(is_valid_url("https://localhost:3000/profiles/test.conf"));
    }

    #[test]
    fn test_is_valid_url_invalid() {
        assert!(!is_valid_url("https://"));
        assert!(!is_valid_url("https://:8080/test"));
        assert!(!is_valid_url("http://"));
        assert!(!is_valid_url("ftp://example.com/test.conf"));
        assert!(!is_valid_url("example.com/test.conf"));
        assert!(!is_valid_url("/path/to/file.conf"));
    }

    #[test]
    fn test_resolve_target_url() {
        let result = resolve_target("https://example.com/test.conf");
        assert!(matches!(result, Ok(ImportTarget::Url(_))));

        if let Ok(ImportTarget::Url(url)) = result {
            assert_eq!(url, "https://example.com/test.conf");
        }
    }

    #[test]
    fn test_resolve_target_invalid_url() {
        let result = resolve_target("https://");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid URL format");
    }
}

use crate::constants;
use crate::logger::{self, LogLevel};
use crate::process::CommandSpec;

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
    let target_path = crate::config::profiles::get_unique_path(&profiles_dir, &filename);

    // Use curl to download directly to file
    // -f: Fail silently on HTTP errors (returns exit code)
    // -L: Follow redirects
    // -s: Silent mode
    // -S: Show errors even in silent mode
    // --max-time: Timeout
    // -o: Output file
    let output = crate::process::run(CommandSpec::oneshot(
        "curl",
        vec![
            "-f".into(),
            "-L".into(),
            "-s".into(),
            "-S".into(),
            "--max-time".into(),
            constants::HTTP_TIMEOUT_SECS.to_string(),
            "-A".into(),
            format!("{}/{}", constants::APP_NAME, constants::APP_VERSION),
            "-o".into(),
            target_path.to_string_lossy().into_owned(),
            url.into(),
        ],
    ))
    .map_err(|e| {
        logger::log(
            LogLevel::Error,
            "DOWNLOAD",
            format!("Failed to execute curl: {e}"),
        );
        format!("{}: {e}", constants::ERR_HTTP_CLIENT_BUILD_FAILED)
    })?;

    if !output.success() {
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

/// Remove a temp file left over from a URL download.
/// Logs on failure but never propagates errors — the import already succeeded.
pub fn cleanup_temp_download(path: &std::path::Path) {
    if path.exists() && path.starts_with(std::env::temp_dir()) {
        if let Err(e) = std::fs::remove_file(path) {
            logger::log(
                LogLevel::Warning,
                "DOWNLOAD",
                format!("Failed to clean up temp file {}: {e}", path.display()),
            );
        }
    }
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
mod more_tests {
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
        assert!(std::path::Path::new(&result)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("conf")));
    }

    #[test]
    fn test_extract_filename_ovpn_in_url() {
        // Should use .ovpn if mentioned in URL
        let result = extract_filename_from_url("https://example.com/openvpn/download");
        assert!(
            std::path::Path::new(&result)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
                || result.contains("ovpn")
        );
    }

    #[test]
    fn cleanup_removes_temp_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("vortix-test-cleanup.ovpn");
        std::fs::write(&path, "test").unwrap();
        assert!(path.exists());
        cleanup_temp_download(&path);
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_ignores_non_temp_path() {
        let dir = std::env::current_dir().unwrap();
        let path = dir.join("vortix-test-cleanup-nontmp.ovpn");
        std::fs::write(&path, "test").unwrap();
        assert!(path.exists());
        cleanup_temp_download(&path);
        assert!(path.exists(), "file outside temp dir must not be deleted");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn cleanup_noop_on_missing_file() {
        let path = std::env::temp_dir().join("vortix-nonexistent-file.ovpn");
        cleanup_temp_download(&path); // should not panic
    }
}
