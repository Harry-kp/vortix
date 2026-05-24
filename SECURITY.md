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
- Optional encrypted secret store using the OS keyring (Keychain on
  macOS, Secret Service on Linux) with AES-256-GCM + argon2id
  fallback for headless installs

## Daemon authentication model (v0.3.0 phase E)

> **Honest framing — this section ships without an independent
> security audit.** v0.3.0 lands the daemon architecture so plans
> downstream can build on it; the auth model documented below has
> NOT been reviewed by an outside party. The corner cases at the
> bottom of this section are the recommended starting points for
> any pre-1.0 audit.

### Threat model

Vortix's optional `vortix daemon` runs as root to perform privileged
network operations (`wg-quick`, `openvpn`, `iptables`/`pfctl`). The
TUI/CLI frontend runs as the user and connects to the daemon over a
Unix domain socket.

**Protected against:**

- A non-root user on the same machine attempting to drive the daemon
  to bring up arbitrary VPN configurations. The daemon refuses
  requests from a UID other than its owning UID via `SO_PEERCRED`
  (Linux) / `getpeereid(2)` (macOS). Filesystem permissions on the
  socket (`mode 0600`, owned by the daemon's effective UID) are the
  secondary guard.
- Casual disk-snooping. Profile configs are mode 0600. The encrypted
  secret store uses keyring-first + AES-256-GCM + argon2id fallback.

**NOT protected against:**

- Kernel exploits or root-equivalent compromise. Anyone with root
  can read `/proc/<daemon-pid>/mem`, attach ptrace, or write to the
  socket bypassing peer-credential checks.
- Container escape. If vortix runs inside a non-isolated container,
  an escape gives the attacker the same privileges as the daemon.
- Side-channel attacks. Timing, cache, network observation.

### Corner cases to re-examine in any pre-1.0 audit

The following are specific scenarios a security review should walk
through before v1.0 ships:

1. **UID race during socket connect.** Between `accept()` and the
   peer-credential check, the connecting process could
   theoretically exec-and-exit. The exec-image check happens once
   at connect time.
2. **Daemon-death failover behavior.** If the daemon dies
   mid-tunnel, the existing `wg-quick` / `openvpn` daemons keep
   running. The next start sees orphan processes via the existing
   plan 008 U5 orphan scan but doesn't auto-adopt; clients see
   "daemon unreachable" via the IPC layer. The fail-closed-on-
   disconnect posture for the killswitch is documented but not
   enforced today.
3. **Filesystem-permissions tampering.** The socket starts at mode
   0600 but if a privileged caller chmods it to 0666, peer-cred
   auth still blocks unauthorized clients — but the threat model
   assumes only the daemon's owning UID can modify the socket's
   perms.
4. **Cryptographic auth alternative.** Today the daemon uses
   kernel-provided peer credentials, no cryptographic tokens. A
   capability-token model (each frontend session gets a fresh
   secret handed via the socket on first connect, all subsequent
   ops carry it) would defend against the UID race in (1) but adds
   protocol complexity. Worth considering pre-1.0.

### What v0.3.0 ships vs what's deferred

v0.3.0 ships the daemon architecture:

- IPC framing + envelope contract (`vortix-core::ipc`)
- Unix socket binding at `${XDG_RUNTIME_DIR}/vortix.sock`
- Filesystem permissions guard (mode 0600)
- Documentation of the auth posture (this section)

Deferred to v0.3.x (the engine wiring follow-up):

- `SO_PEERCRED` / `getpeereid` enforcement in the accept loop —
  documented as required, implemented as the daemon's engine
  routing lands
- Read-only ops bypass the daemon entirely — `vortix status` and
  `vortix list` operate against the filesystem; only `up`/`down`/
  `killswitch` need privileged execution
- Audit log of privileged operations in the journal

Pre-1.0 hardening (post-v0.3.x):

- Independent security audit covering the corner cases above
- Cryptographic capability tokens (option in addition to
  `SO_PEERCRED`)
- seccomp filters narrowing the daemon's syscall surface
- AppArmor / SELinux reference profiles

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers in our release notes (unless you prefer to remain anonymous).
