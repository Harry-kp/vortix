//! Minimal `.ovpn` parser — enough to detect auth-user-pass mode.

use vortix_core::ports::tunnel::{ParseError, ParsedProfile};

/// Parsed `OpenVPN` profile body.
#[derive(Debug, Default, Clone)]
pub struct OvpnParsedProfile {
    /// Whether the profile expects interactive auth (`auth-user-pass` directive
    /// without a file path).
    pub interactive_auth: bool,
    /// The raw config text — `openvpn` consumes the on-disk file, so this is
    /// retained for introspection only.
    pub raw: String,
}

impl ParsedProfile for OvpnParsedProfile {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Parse a `.ovpn` body into [`OvpnParsedProfile`].
///
/// # Errors
///
/// Currently returns `Ok` for any UTF-8 input; future stricter validation
/// (key blocks, malformed directives) can add error variants.
pub fn parse_ovpn_conf(text: &str) -> Result<OvpnParsedProfile, ParseError> {
    let mut interactive_auth = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // `auth-user-pass` alone (no file path) triggers interactive auth.
        if line == "auth-user-pass" {
            interactive_auth = true;
        }
    }

    Ok(OvpnParsedProfile {
        interactive_auth,
        raw: text.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_interactive_auth() {
        let text = "client\nproto udp\nauth-user-pass\nremote example.com 1194\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(p.interactive_auth);
    }

    #[test]
    fn ignores_auth_with_file() {
        let text = "client\nauth-user-pass /etc/openvpn/creds.txt\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.interactive_auth);
    }

    #[test]
    fn skips_comments() {
        let text = "# auth-user-pass\n; auth-user-pass\nclient\n";
        let p = parse_ovpn_conf(text).unwrap();
        assert!(!p.interactive_auth);
    }
}
