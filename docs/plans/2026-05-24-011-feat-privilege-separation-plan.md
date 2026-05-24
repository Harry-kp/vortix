---
plan_id: 2026-05-24-011
title: "feat: Privilege separation — root worker + unprivileged frontend"
type: feat
status: completed
created: 2026-05-24
target_version: 0.5.0
target_branch: TBD (post plan 010)
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
motivating_issue: 153
depends_on: [2026-05-24-010]
---

# feat: Privilege separation — root worker + unprivileged frontend

> **Status: deferred.** This plan is a document-only artifact in PR
> #201. Execution requires plan 010 to land first.

## Problem Frame

Issue #153 (run without sudo) has been open since March, labeled
`security`. Today the entire vortix binary runs as root — both the
TUI and the subprocess invocations (`wg-quick`, `openvpn`, firewall
rules). A user reading their VPN status in the TUI does not need
root; only the actual `up`/`down`/`killswitch` operations do.

Privilege separation splits vortix into two processes:

- **Privileged worker** (`vortix daemon` running as root, or
  setuid, or via `pkexec`/`sudo` once per session) — hosts the
  Engine actor, executes the privileged subprocess work
- **Unprivileged frontend** (the TUI and most CLI commands) — runs as
  the user, talks to the worker over the IPC layer (plan 010)

## Summary

Build on plan 010's IPC layer. The privileged daemon BECOMES the
engine host. The frontend connects to it via `EngineHandle::Remote`.
Read-only operations (`status`, `list`, `journal tail`) work without
root once the daemon is reachable. Privileged operations
(`up`/`down`/`killswitch`) are routed to the daemon, which authorizes
based on the socket's connecting UID matching the daemon's owner.

## Scope Boundaries

**In scope:**
- Plan 010 IPC layer is the prerequisite — this plan assumes it
- Daemon installs and runs via systemd / launchd as root, owned by
  the user
- Frontend auto-launches daemon via `pkexec`/`sudo` if not running
- Read-only commands work without daemon at all (read sidecars
  directly)
- Audit log of privileged operations in the journal
- Documentation for the new permission model

**Deferred:**
- Linux capabilities (CAP_NET_ADMIN) instead of full root —
  worth doing but not for v0.5
- macOS Endpoint Security Framework hardening — not on the path
- SELinux / AppArmor profiles — packaging concern, not architecture

**Outside this product's identity:**
- Vortix becomes a multi-user VPN gateway — no
- Vortix accepts external admin commands over network — no

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | `vortix status`, `vortix list`, `vortix journal tail` work without root or daemon presence |
| R2 | `vortix up <profile>` works with the daemon running; without daemon, prompts to start it |
| R3 | The daemon refuses commands from a UID different from its owner |
| R4 | Privileged operations are logged to the journal with `actor: <uid>` |
| R5 | Existing `sudo vortix up` continues to work (one-shot mode) for users who don't install the daemon |

## Key Technical Decisions (deferred)

- **Worker auth: socket peer UID matching.** Linux `SO_PEERCRED`,
  macOS `getpeereid`. No cryptographic tokens.
- **The daemon does NOT auto-start.** Users explicitly opt in via
  `systemctl enable vortix-daemon` or `launchctl load`.
- **Fallback to one-shot sudo mode is preserved** — power users who
  don't want a daemon can keep `sudo vortix up`.
- **Read-only operations bypass the daemon when possible.** Reading
  `~/.config/vortix/profiles/*.meta.toml` doesn't need privilege.

## Open Design Questions

1. What's the daemon's restart story if it dies with an active
   tunnel?
2. How does the daemon discover which user "owns" it (multi-user
   machines)?
3. Should the daemon's killswitch enforcement be aggressive (fail
   closed if daemon dies) or conservative (release on exit)?
4. setuid binary vs. systemd-managed daemon vs. pkexec wrapper —
   which is the canonical recommendation?

## Verification (high-level)

- `vortix status` works as a normal user
- `vortix up <profile>` brings up VPN with daemon installed; clear
  error without daemon
- Process inspection shows the TUI is NOT running as root
- Audit log entries appear for every up/down/killswitch
- `sudo vortix up <profile>` still works (one-shot mode preserved)

## What this plan unblocks

- Issue #153 (run without sudo) — direct solve
- Better security posture — auditable, principle-of-least-privilege
- Future: capability-based access (CAP_NET_ADMIN only) — incremental

## Estimated effort

4–6 weeks. This is genuinely hard work — system integration, security
review, testing across init systems. Should be done with a
documentation pass and a security threat model alongside.
