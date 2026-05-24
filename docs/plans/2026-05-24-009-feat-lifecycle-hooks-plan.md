---
plan_id: 2026-05-24-009
title: "feat: Lifecycle hooks (pre/post connect/disconnect)"
type: feat
status: deferred-to-v0.3.x
created: 2026-05-24
target_version: 0.4.0
target_branch: TBD (post v0.3.0 GA)
origin: docs/brainstorms/2026-05-24-architectural-completion-requirements.md
motivating_issue: 36
---

# feat: Lifecycle hooks (pre/post connect/disconnect)

> **Status: deferred.** This plan is a document-only artifact in PR
> #201. Execution happens in a future PR after v0.3.0 ships.

## Problem Frame

Issue #36 has been open since February asking for pre/post connect and
disconnect scripts. Today users with this need run vortix via a shell
wrapper that pre/post-runs their own commands — clunky, easy to miss
disconnect cleanup, no integration with the engine's actual state
transitions.

The architectural migration v1 lays the right foundation: the
`EngineEvent` stream and journal broadcast are already the seam this
feature needs. What's missing is a `Hook` trait, a registry, and a way
to dispatch hooks at the right FSM transitions without coupling the
engine to a specific execution model (shell out vs. embedded Rust
plugin vs. webhook).

## Summary

Add a `Hook` trait + `HookRegistry` to `vortix-core`. At the FSM
transition boundaries (entering Connecting, entering Connected, leaving
Connected, entering Disconnected with failure), the EngineHandle actor
publishes a `LifecycleEvent` that registered hooks consume. The first
shipping hook impl is a `ShellHook` that runs user-defined shell
commands; future impls can include a `WebhookHook`, a `JournalHook`
(already there in event form), and embedded Rust plugins.

## Scope Boundaries

**In scope:**
- `Hook` trait + `HookRegistry` in `vortix-core::engine::hooks`
- `LifecycleEvent` enum: `PreConnect`, `PostConnect`, `PreDisconnect`,
  `PostDisconnect`, `ConnectFailed`, `Reconnecting`
- `ShellHook` impl in `crates/vortix/` (binary, not core — has subprocess
  dependency)
- Configuration via `settings.toml`:
  ```toml
  [[hooks]]
  event = "post_connect"
  command = ["/usr/local/bin/notify-send", "VPN up"]
  ```
- Timeout per hook (default 5s; cancellable)
- Hook failures are logged but never block the FSM transition
- Documentation update in `docs/MIGRATION.md` for v0.4.0

**Deferred to later:**
- Webhook (HTTP POST) impl — needs HTTP client, retry, auth
- Rust plugin impl — requires dynamic loading (libloading) which has
  cross-platform pain
- Hook ordering / chaining
- Per-profile hooks (just global hooks at v0.4.0)
- Hook templating (substituting `$VORTIX_PROFILE`, `$VORTIX_IP`, etc.)

**Outside this product's identity:**
- Vortix becomes a job scheduler — that's not the product
- Hooks that modify engine state (e.g., a hook that says "actually
  don't connect") — hooks are observers, not gates

## Requirements

| ID | Requirement |
|----|-------------|
| R1 | Users can register shell-command hooks via `settings.toml` for the six lifecycle events |
| R2 | Hook failures are logged + journal-emitted but never block the FSM transition |
| R3 | Hooks run with a configurable timeout (default 5s); timeouts cancel the subprocess |
| R4 | Hook env vars include `VORTIX_PROFILE`, `VORTIX_PROTOCOL`, `VORTIX_EVENT`, `VORTIX_IP` (if known) |
| R5 | Existing users (no `[[hooks]]` config) see zero behavior change |

## Key Technical Decisions (deferred — to be made during real planning)

- **Hooks fire async, not blocking the FSM transition.** A 30-second
  `notify-send` shouldn't delay vortix declaring "Connected."
- **Hooks consume the journal broadcast, not a separate channel.** The
  hook registry subscribes to `EngineHandle::subscribe()` and filters
  for lifecycle events. Reuses existing infrastructure.
- **`ShellHook` lives in the binary, not `vortix-core`.** Subprocess
  execution is a CommandRunner concern; `vortix-core` stays pure.
- **No environment-variable secret leakage.** When passing
  `VORTIX_PROFILE` to hooks, the secret store is never touched. If a
  hook needs the OpenVPN auth blob it can read its own files.

## Open Design Questions (to resolve at planning time)

1. Hook config schema — inline in `settings.toml` or separate
   `hooks.toml`?
2. Hook discovery — only `settings.toml`-declared, or also a
   conventional `~/.config/vortix/hooks.d/*.sh` dropbox?
3. Hook output capture — discard, log to journal, or attach to next
   event?
4. Hook execution model — `tokio::process::Command::spawn` directly,
   or via the existing `CommandRunner` port?

## Verification (high-level)

- Hooks fire in the expected order around a `Connect` flow with all
  six lifecycle events represented.
- A 30-second sleep hook does NOT delay the FSM's `Connected`
  declaration.
- A hook that exits non-zero produces a journal event but doesn't
  break the connection.
- Removing all `[[hooks]]` config restores zero-overhead operation.

## What this plan unblocks

- Issue #36 (lifecycle hooks) — direct solve
- Notification integration use cases — users wire `notify-send` /
  `osascript` / `terminal-notifier`
- Custom DNS / firewall coordination — users run their own
  `iptables`/`pfctl` rules
- Audit logging — wire a hook to write to syslog or a SIEM endpoint

## Estimated effort

2–3 weeks of one engineer's time, including testing across macOS and
Linux with at least three realistic hook scenarios.
