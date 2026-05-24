---
plan_id: 2026-05-24-013
title: "feat: Socket audit port (per-process network inspection)"
type: feat
status: completed
created: 2026-05-24
target_version: 0.4.0
target_branch: TBD (post v0.3.0 GA)
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
motivating_issue: 168
---

# feat: Socket audit port (per-process network inspection)

> **Status: deferred.** This plan is a document-only artifact in PR
> #201. Execution happens in a future PR after v0.3.0 ships.

## Problem Frame

Two issues motivate this port:

- **#168 — Active Connections Audit** (labeled `security`):
  per-socket check that traffic is actually going through the VPN, not
  leaking around it.
- **#166 — Network Activity Table:** per-process network usage view
  in the TUI.

Both need the same data: a list of every open socket on the system
with owning PID, local/remote addresses, and which interface the
traffic is using. Today there's no port for this.

The migration v1 makes adding this port mechanical — it follows the
same shape as `DnsResolver`, `Interface`, etc. The platform-specific
impls are the real work (`lsof`/`netstat`/`ss` on Linux, `lsof`/`nettop`
on macOS, `Get-NetTCPConnection` on Windows).

## Summary

Add a `SocketAudit` port to `vortix-core::ports`. Per-OS impls in
`vortix-platform-{macos,linux,windows}` shell out to the native tool
and parse the output. The port returns a `Vec<SocketSnapshot>` with
PID, command name, local/remote endpoint, protocol, and the routing
interface.

## Scope Boundaries

**In scope:**
- `SocketAudit` trait in `vortix-core::ports::socket_audit`
- `SocketSnapshot` data model
- Linux impl: parse `/proc/net/tcp{,6}` + `/proc/<pid>/fd/*`
- macOS impl: shell out to `lsof -i -P -n`
- Windows impl: stub (`PlatformUnsupported` per plan 008 U4 model)
- Add the port to `Platform` aggregate
- One consumer wired: a `vortix audit` CLI subcommand printing the
  table

**Deferred:**
- TUI integration (#166 widget) — separate feature plan
- Continuous monitoring / streaming snapshots — pull-based for v1
- Filter-by-app helpers (e.g., "show me Firefox's sockets")

**Outside this product's identity:**
- Vortix as a process monitor / activity tracker — no
- Network packet inspection / DPI — no

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | `SocketAudit::snapshot() -> Vec<SocketSnapshot>` returns all open sockets on the current machine |
| R2 | `SocketSnapshot` includes: pid, command, local_addr, remote_addr, protocol (tcp/udp), interface |
| R3 | Linux impl works without root for non-foreign-user sockets |
| R4 | macOS impl works without root for non-foreign-user sockets |
| R5 | `vortix audit` prints a sorted table; `--json` returns the same data |
| R6 | When VPN is up, the `interface` field correctly reflects whether traffic uses the tunnel |

## Key Technical Decisions

- **Pull-based, not stream.** A single snapshot covers the
  motivating use cases. Streaming adds complexity.
- **Native tools, not `procfs` crate or platform-specific bindings.**
  `lsof` / `ss` outputs are stable enough; vortix already shells out
  for everything else.
- **Best-effort PID resolution.** When the owning user is different
  and we can't read `/proc/<pid>/comm`, fall back to "unknown".

## Open Design Questions

1. Cache strategy — re-fetch on every call, or cache for N seconds?
2. Handle UDP separately or unified?
3. IPv6 — first-class or deferred?
4. macOS without root sees fewer sockets — document or warn?

## Verification

- A known socket (e.g., `nc -l 12345` in the background) appears in
  `vortix audit` output
- After `vortix up`, traffic from a curl through the tunnel shows
  the tunnel interface in `vortix audit`
- Snapshot completes in <500ms on a machine with 200+ open sockets

## What this plan unblocks

- Issue #168 (active connections audit) — direct solve
- Issue #166 (network activity table) — provides the data model
- Future leak-detection features — "any non-VPN traffic when VPN is
  up?" becomes answerable

## Estimated effort

2–3 weeks. The data model is straightforward; the parsing logic for
each OS's native tool is most of the time.
