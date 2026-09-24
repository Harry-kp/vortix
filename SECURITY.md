# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: (current) |
| 0.3.x   | :white_check_mark: |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

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
- OpenVPN credentials are stored in `~/.config/vortix/auth/<profile>.auth`
  with `600` permissions; reachable only by the owning user

## Multi-tunnel trust assumptions (v0.4.0)

> The multi-connection release lands the ability to run more than one
> VPN tunnel concurrently. The sections below document the new trust
> boundaries that come with it. These have not yet been reviewed by an outside party — surfaced here
> so downstream audits know what to walk through.

### `vpn-only` allow-list

In `vpn-only` mode the firewall is default-drop and allows only the
server IPs of live tunnels plus the endpoints of tunnels still
starting. An imported profile's `remote` addresses are reachable only
while that profile is starting or connected; nothing is allow-listed
for profiles that are merely imported.

**Residual risk.** While a profile is starting, every endpoint it
names is reachable, so a profile with many attacker-chosen `remote`
lines opens egress to those IPs for the length of the connect.

**Mitigation.** Only import profiles from VPN providers you trust, and
audit the `remote` lines of profiles from other sources.

### Credential-safe file handling via `write_secret_file`

OpenVPN auth files (`~/.config/vortix/auth/<profile>.auth`) and
generated runtime configs hold credential material. An older
implementation opened the path with `O_CREAT` and then called
`chmod(2)` to tighten perms — a TOCTOU window during which a local
attacker could read the file at default-umask perms, or substitute a
symlink to a target they wanted Vortix to clobber.

**Mitigation.** Credential writes go through
`write_secret_file` in `crates/vortix/src/config/secret.rs`, which:

- Opens the parent directory with `O_DIRECTORY | O_NOFOLLOW` and
  creates the file with `openat(2)` against that descriptor
- Sets `O_NOFOLLOW` on the file so a pre-placed symlink fails the open
- Sets `O_EXCL` so the open fails if the path already exists
- Creates with mode `0600` directly via the `open(2)` mode argument —
  no separate `chmod`, so no TOCTOU window — and fsyncs before return

Other user-owned state (settings, profiles, metadata) goes through
`crates/vortix/src/config/owned_file.rs`: `write_user_file_atomic`
replaces a file atomically inside an owner-checked directory without
following links, and `create_user_dir` creates directories at `0700`
via `DirBuilder::mode(0o700)` and narrows existing ones to owner-only
rather than relying on the umask.

### Fwmark hijack

WireGuard tunnels without explicit `FwMark` directives can route a
secondary tunnel's handshake material *through the primary tunnel* —
a credential/metadata exposure across operator trust boundaries.
Vortix surfaces this as a persistent warning in the Connection
Details panel; for the user-facing explanation and remediation, see
[`docs/multi-tunnel-fwmark.md`](docs/multi-tunnel-fwmark.md).

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (unless you prefer to remain anonymous).
