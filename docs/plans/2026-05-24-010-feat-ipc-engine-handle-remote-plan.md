---
plan_id: 2026-05-24-010
title: "feat: IPC layer — EngineHandle::Remote (daemon mode foundation)"
type: feat
status: completed
created: 2026-05-24
target_version: 0.4.0
target_branch: TBD (post v0.3.0 GA)
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
motivating_issue: 16
depends_on: []
blocks: [2026-05-24-011]  # privilege separation depends on IPC
---

# feat: IPC layer — EngineHandle::Remote (daemon mode foundation)

> **Status: deferred.** This plan is a document-only artifact in PR
> #201. Execution happens in a future PR after v0.3.0 ships.

## Problem Frame

Issue #16 (auto-connect on startup / daemon mode) has been open since
January. The architectural migration v1 built `EngineHandle::Local` —
the actor that wraps the FSM and exposes `execute`/`snapshot`/`subscribe`
in-process. To support a daemon, the same handle shape needs a `Remote`
variant where the actor lives in a different process and the frontend
(TUI or CLI) talks to it over IPC.

This plan also unblocks plan 011 (privilege separation) — once
`EngineHandle::Remote` exists, the privileged worker can BE the actor
host and the unprivileged frontend a Remote client.

## Summary

Add `EngineHandle::Remote(RemoteHandle)` with the same API surface as
`Local`. The IPC transport is a Unix domain socket carrying length-
prefixed JSON messages. A `vortix daemon` subcommand hosts the actor;
`vortix --daemon-socket /path` makes the existing CLI/TUI talk to that
daemon instead of spawning its own engine.

## Scope Boundaries

**In scope:**
- `EngineHandle::Remote(RemoteHandle)` variant + same API
  (`execute`/`snapshot`/`subscribe`)
- Unix domain socket transport with length-prefixed JSON framing
- `vortix daemon [--socket /path]` subcommand
- `VORTIX_DAEMON_SOCKET` env var auto-detection
- systemd unit example in `examples/` for Linux
- launchd plist example for macOS
- Documentation in `docs/MIGRATION.md` for v0.4.0
- Auth: filesystem permissions on the socket (mode 0600, owned by
  effective user) — no cryptographic auth in v0.4
- Reconnection logic if the daemon restarts mid-session

**Deferred:**
- Cross-machine IPC (TCP/TLS) — local Unix socket only
- gRPC or protobuf — JSON is human-debuggable and fine for the
  expected message volume
- Multi-tenant daemons (one daemon per user)

**Outside this product's identity:**
- Vortix becomes a network daemon accepting external connections — no
- Vortix federates across machines — no

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | `vortix daemon` runs in the foreground and hosts the EngineHandle actor |
| R2 | `EngineHandle::Remote::execute(Connect)` over the socket produces the same observable behavior as `Local::execute` |
| R3 | `EngineHandle::Remote::subscribe()` streams `EngineEvent`s from the daemon over the socket |
| R4 | If the daemon dies, Remote consumers see the disconnection and surface "daemon unreachable" |
| R5 | The TUI auto-detects `VORTIX_DAEMON_SOCKET` and uses Remote if set; otherwise spawns Local |
| R6 | systemd / launchd examples are documented and tested manually |

## Key Technical Decisions (deferred — to be made during planning)

- **Transport: Unix domain socket + length-prefixed JSON.** Simple,
  debuggable with `socat`, no extra dependencies beyond what
  `tokio::net::UnixStream` already provides.
- **Framing: 4-byte big-endian length prefix + JSON body.** Standard
  pattern; no need for protobuf complexity at v0.4.
- **One socket per daemon, single client at a time** initially.
  Concurrent client support comes when needed.
- **The daemon is the truth source for FSM state.** If the daemon
  restarts, Remote consumers reconnect and re-fetch snapshot.

## Open Design Questions (to resolve at planning time)

1. Backpressure model for `subscribe()` — drop-oldest, drop-newest, or
   block?
2. Daemon lifecycle — does it tear down VPN on exit, or leave the
   tunnel up for the next connect?
3. Auth posture — filesystem perms only, or also a token in the
   socket?
4. Should `Remote` automatically fall back to spawning a Local engine
   if the socket isn't reachable?

## Verification (high-level)

- `vortix daemon` + `vortix up <profile>` over the socket bring up a
  VPN identically to non-daemon mode
- Killing the daemon mid-session surfaces "daemon unreachable" within
  2s
- The TUI works against a Remote engine
- `subscribe()` over the socket delivers events with <100ms latency

## What this plan unblocks

- Issue #16 (daemon mode) — direct solve
- Plan 011 (privilege separation) — depends on this IPC layer
- Multi-frontend support (e.g., a web UI talking to the daemon) —
  future work, but the seam is there

## Estimated effort

3–4 weeks. The transport layer is straightforward; the integration
work (TUI, CLI, reconnection logic, systemd integration) is most of
the time.
