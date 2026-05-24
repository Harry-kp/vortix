---
date: 2026-05-24
topic: daemon-engine-handle
---

# Daemon-First + `EngineHandle` (Phases A & B)

## Summary

Idea 4 of 7 from the vortix target-architecture ideation splits into two phases. **Phase A** (the `EngineHandle` decoupling, killing `App: Deref<VpnEngine>`, App-as-view) has been **merged into the Engine FSM + Event Journal brainstorm** at `docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md` — see requirements R23-R30 there and the bundled scope rationale in that doc's Summary. **Phase B** (the actual `vortixd` daemon process, IPC transport, lifecycle, install-as-service question) is **deferred** to a separate later brainstorm pass.

## Why split

The two refactors deliver fundamentally different kinds of value at different costs:

- **Phase A** is architectural plumbing that costs about one big-bang PR and unblocks every other survivor (testability, library embedding, daemon-readiness, hooks-readiness, audit-log-readiness). The user-visible behavior is unchanged.
- **Phase B** introduces a new operating-system-level process with its own lifecycle, socket location, version-skew rules, multi-user auth question, and install story (`vortix install-daemon` system-service installer for users who want killswitch-survives-reboots behavior). Each of these is a real product decision that benefits from being made when the engine surface is stable.

Bundling Phase B into idea 4's first PR would have:

- Forced premature decisions on socket location (`$XDG_RUNTIME_DIR` vs `/var/run` vs per-user vs system-wide)
- Forced premature decisions on wire protocol (newline-delimited JSON vs MessagePack vs JSON-RPC vs gRPC)
- Forced premature decisions on installer scope (does cargo-dist start managing a launchd plist? does Homebrew formula change?)
- Introduced version-skew handling between the `vortix` CLI and `vortixd` process that needs its own discipline
- Risked destabilizing the existing release pipeline (already fragile per the recent `cf76218` token-handling fix)

Phase A is designed so Phase B is **additive**: the `EngineHandle` enum's `Local(LocalHandle)` variant ships now; a future `Remote(RemoteHandle)` variant lands as a new arm with zero callsite changes outside the handle module.

## Phase A scope (in the merged doc)

See `docs/brainstorms/2026-05-24-engine-fsm-event-journal-requirements.md`, specifically:

- **R23-R30** — the `EngineHandle` enum, Command/Query/Subscribe API, `LocalHandle` actor, `App`-as-view restructure, public API surface, test seam
- **A9** — embedding consumer actor (Tauri/MCP/system-tray)
- **AE10-AE13** — acceptance examples for the handle behavior
- **Out-of-scope bullet about Phase B** — explicit deferral

## Phase B scope (deferred — future brainstorm)

When the project is ready to take on Phase B (likely after ideas 5-7 ship and v0.3.0 ROADMAP work begins), brainstorm topics to resolve:

- **Daemon lifecycle model** — hybrid auto-spawn (per-user daemon, idle-exit), always-on system service (installer registers systemd unit / launchd plist / Windows Service), or hybrid with opt-in `vortix install-daemon` upgrade path
- **IPC transport** — Unix socket on macOS/Linux + Windows named pipe on Windows; or gRPC over localhost TCP; or another transport
- **Wire protocol** — newline-delimited JSON (debuggable, multi-language) vs MessagePack (compact) vs Protobuf (versioned, tooled) vs JSON-RPC 2.0 (standard envelope)
- **Socket location and permissions** — `$XDG_RUNTIME_DIR/vortix/vortixd.sock` mode 0600 (per-user) vs `/var/run/vortix.sock` mode 0660 + `vortix` group (system-wide) vs both with mode auto-selection
- **Authentication** — implicit (peer-uid via SO_PEERCRED) vs explicit token-based; single-user vs multi-user dev box behavior
- **Privileged operations boundary** — daemon-as-root architecture (the structural fix to idea 1's `sudo vortix up` UX) — installed-as-system-service variant only, with documented fallback when daemon runs as user
- **Backward compatibility** — when daemon isn't running, does `vortix` (a) auto-spawn one, (b) fall back to in-process, (c) error out and direct the user to install the daemon, or (d) some mix
- **Version-skew handling** — if `vortixd` is older than `vortix` CLI (or vice versa), reject / downgrade / upgrade
- **Distribution surface** — what changes to Homebrew formula, cargo-dist config, AUR package, Nix flake, npm package; what stays the same; what optional `vortix install-daemon` step looks like
- **`RemoteHandle` impl** — the second `EngineHandle` enum variant; reconnection logic; subscription resumption after daemon restart
- **Multi-user behavior** — per-user daemon (one per logged-in user) vs single daemon (shared, with profile-store ACLs)
- **Auto-connect on boot** (v0.3.0 ROADMAP item) — only landable with a system-service daemon

This list is the seed for the Phase B brainstorm; not a planning document. Most items will need their own dialogue and decision.

## Status

- **Phase A**: in scope of the merged FSM + EngineHandle brainstorm. Requirements R23-R30 are the canonical record.
- **Phase B**: deferred. No requirements, no PR, no commitments. Re-open as a new brainstorm when project pressure (v0.3.0 daemon mode, auto-connect, killswitch-survives-reboot, multi-user team management) demands it.
