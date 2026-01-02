# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Vortix, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainer directly or open a private security advisory on GitHub
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium/Low: Next release cycle

## Security Considerations

Vortix handles sensitive VPN configurations. Key security measures:

- Config files stored with `600` permissions (owner read/write only)
- No config data transmitted externally
- Root privileges required only for network interface operations
- No telemetry or analytics collected

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (unless you prefer to remain anonymous).
