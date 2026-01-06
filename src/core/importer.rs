use std::path::PathBuf;

/// Target for an import operation
#[derive(Debug, Clone)]
pub enum ImportTarget {
    Url(String),
    File(PathBuf),
    Directory(PathBuf),
}

/// Helper to expand paths with ~ to standard `PathBuf`
pub fn expand_home(path_str: &str) -> PathBuf {
    if let Some(stripped) = path_str.strip_prefix("~/") {
        if let Some(home) = crate::utils::home_dir() {
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
