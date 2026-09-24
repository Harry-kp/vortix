# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
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

## Multi-tunnel trust assumptions (v0.4.0 phase)

> The multi-connection release lands the ability to run more than one
> VPN tunnel concurrently. The sections below document the new trust
> boundaries that come with it. These have not yet been reviewed by an outside party — surfaced here
> so downstream audits know what to walk through.

### OpenVPN `remote` IP allow-list trust assumption

When the killswitch is in `AlwaysOn` mode, Vortix synthesizes its
firewall ruleset by allow-listing every `remote <host> <port>`
directive in every imported `.ovpn` profile. We do this because at
ruleset-synthesis time we do not yet know which `remote` an OpenVPN
process will eventually pick (OpenVPN selects at connect time, and
the `remote-random` directive randomizes selection per-attempt).

**Concrete threat.** A `.ovpn` profile shipped with `remote 0.0.0.0`
and `remote-random` (or, more realistically, a long list of
attacker-controlled IPs) can rotate destinations across arbitrary
internet endpoints. Every IP listed in any such profile is
*permanently allow-listed* through the killswitch — including when
no Vortix tunnel is up — providing an egress path for any traffic
the attacker can route to those IPs. The killswitch's job is to be
the last line of defense; this v1 posture makes that defense
conditional on the user's profile-import trust.

**Mitigation.** Only import `.ovpn` profiles from VPN providers you
trust. Vortix v0.4.x relies on the user's profile-import flow as the
trust gate (this is `NG5` in the multi-connection plan — the sharper
fix, OpenVPN management-socket integration that allow-lists only the
*actually-connected* remote, is deferred to v2). If you ingest
profiles from untrusted sources, audit the `remote` lines manually
and remove the killswitch's `AlwaysOn` mode until v2 ships.

### Credential-safe file handling via `write_secret_file`

OpenVPN auth files (`~/.config/vortix/auth/<profile>.auth`) and
in-memory generated configs hold credential material. The historical
implementation in `crates/vortix/src/utils.rs` opened the path with
`O_CREAT` and then called `chmod(2)` to tighten perms — a TOCTOU
window during which a local attacker could win a race against the
chmod and read the file at default-umask perms, or substitute a
symlink to a target they wanted Vortix to clobber.

**Mitigation (U12, commit `cb25725`).** Credential writes now route
through `write_secret_file`, which:

- Opens the parent directory via `openat(2)` against a directory
  file descriptor obtained at startup
- Sets `O_NOFOLLOW` so a pre-placed symlink at the target path fails
  the open rather than dereferencing
- Sets `O_EXCL` so the open fails if the path already exists,
  forcing an explicit unlink before rewrite
- Creates with mode `0600` directly via the `open(2)` mode argument —
  no separate `chmod` call, so no TOCTOU window

The combined effect is that symlink attacks against
`~/.config/vortix/*.auth` (and the WireGuard/OVPN runtime configs
written under `~/.config/vortix/tmp/<session>/`) are mitigated. The
session subdirectory itself is created at mode `0700` via
`DirBuilder::mode(0o700)` rather than relying on the inherited
umask.

### Fwmark hijack

WireGuard tunnels without explicit `FwMark` directives can route a
secondary tunnel's handshake material *through the primary tunnel* —
a credential/metadata exposure across operator trust boundaries.
Vortix surfaces this as a persistent warning in the Connection
Details panel; for the user-facing explanation and remediation, see
[`docs/multi-tunnel-fwmark.md`](docs/multi-tunnel-fwmark.md).

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (unless you prefer to remain anonymous).
