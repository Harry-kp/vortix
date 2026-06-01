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
- Casual disk-snooping. Profile configs and `auth/<profile>.auth`
  files are mode 0600.

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

## Multi-tunnel trust assumptions (v0.4.0 phase)

> The multi-connection release lands the ability to run more than one
> VPN tunnel concurrently. The sections below document the new trust
> boundaries that come with it. As with the daemon section above,
> these have not yet been reviewed by an outside party — surfaced here
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

### Daemon UID-confidential `TunnelSnapshot` contract

Multi-tunnel adds a `TunnelRegistry` whose snapshots
(`TunnelSnapshot { profile_id, role, conn_state, telemetry, ... }`)
flow to the TUI/CLI over the daemon's Unix socket. These snapshots
carry profile metadata — names, peer endpoints, AllowedIPs — that
should not cross UID boundaries on a multi-user host.

**Boundary.** The daemon socket binds at mode `0600` and is owned by
the daemon's effective UID; on `accept()` the daemon enforces a peer-
credential check via `SO_PEERCRED` (Linux) / `getpeereid(2)` (macOS)
and refuses requests from any UID other than its owner. The two
guards stack: filesystem perms keep casual readers out, peer-cred
auth blocks privileged callers who relax those perms.

**What this protects.** Cross-UID isolation of tunnel snapshots —
another user on the same machine cannot read which profiles you have
imported, which tunnel is currently primary, or peer endpoint
addresses by connecting to the socket. Subscriptions
(`Subscribe`/`Stream`) inherit the same gate.

**What this does not protect.** Root-equivalent compromise (`ptrace`,
`/proc/<pid>/mem`, kernel exploits) still has unconstrained access —
see the "NOT protected against" list in the daemon section above.

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
