---
id: 2026-05-24-architectural-completion
title: "Architectural completion audit — what's missing after migration v1"
status: complete
type: requirements
created: 2026-05-24
related:
  - 2026-05-24-cargo-workspace-split-requirements.md
  - 2026-05-24-commandrunner-port-requirements.md
  - 2026-05-24-capability-ports-platform-requirements.md
  - 2026-05-24-tunnel-trait-enum-dispatch-requirements.md
  - 2026-05-24-engine-fsm-event-journal-requirements.md
  - 2026-05-24-config-profile-secret-stack-requirements.md
posture: preemptive  # asked before any new feature pressure surfaced
---

# Architectural completion audit — what's missing after migration v1

## Problem frame

PR #201 lands a six-plan architectural migration and ships as v0.3.0. The
maintainer is asking: with the migration "almost done," is there anything
the architecture is still missing that would either (a) destabilize over
the 1–2 year horizon as features land, or (b) force each new feature to
re-litigate abstractions that should already exist?

This is a **preemptive audit**, not a reactive one. No specific user
complaint motivated this brainstorm — the maintainer wants a sweep
before the architectural-context cache decays and before v0.3.0 starts
attracting feature work. The audit is dual-tracked: cheap-now items ship
inside PR #201 alongside the rollout work; multi-week items land as plan
documents that future PRs execute.

## Goals

1. Identify every architectural seam that the next 1–2 years of features
   (per the open issues backlog) would have to retrofit if missing.
2. Land the cheap-now seams in PR #201 itself — bundled with the v0.3.0
   ship.
3. Capture the multi-week subsystems as plan documents (008–013) so that
   when their motivating feature lands, the plan exists.
4. Make explicit which gaps are deliberately *not* being closed
   (premature, no demand, or genuinely better deferred).

## Non-goals (explicit)

- **Cloud / fleet ProfileStore.** The `ProfileStore` trait exists for
  this, but a single `FsProfileStore` impl is fine. Adding a second
  impl with no real consumer is premature.
- **Mobile / web frontends.** No signal in the issue backlog or user
  cohort suggests a non-TUI frontend within the horizon.
- **Error-type unification umbrella.** Per-port `thiserror` enums
  (`ProcessError`, `TunnelError`, `JournalError`, `ProfileStoreError`,
  `SecretStoreError`) work and surface the right context at each
  boundary. An umbrella `VortixError` would obscure rather than
  clarify.
- **Async FSM rewrite.** The `tokio::task::spawn_blocking` wrapper
  around the sync FSM is fine for years. Making the FSM natively async
  buys nothing concrete.
- **Publishing internal crates to crates.io.** `vortix-core`,
  `vortix-config`, etc. stay `publish = false`. **Permanent
  architectural invariant** (not "until an external consumer
  materializes"): the binary `vortix` is the only crates.io artifact
  and `@harry-kp/vortix` is the only npm package, full stop. If a
  future external consumer wants the API surface, they vendor it or
  fork it. This decision is captured durably in
  [`docs/architecture-migration-v1.md`](../architecture-migration-v1.md#distribution-posture-single-crate-single-npm)
  so future plans don't re-litigate it.
- **Lower-level features below the existing ports.** Things like
  alternative QUIC-based VPN protocols, raw socket manipulation, or
  custom kernel modules. The Tunnel port admits them when needed;
  there's no work to do until then.

## Open issues backlog (the input to the audit)

The 19 open issues at audit time, grouped by which architectural seam
they would exercise:

| Issue | Title | Exercises seam |
|---|---|---|
| #16 | Auto-connect on startup (daemon mode) | IPC layer (plan 010) |
| #17 | Windows Support | Platform port (plan 008 U4 stub; full Windows impl deferred) |
| #36 | Lifecycle hooks (pre/post connect scripts) | Lifecycle hooks (plan 009) |
| #153 | Run without sudo | Privilege separation (plan 011) |
| #161 | WireGuard handshake timeout & health monitoring | Engine FSM `Connected{health}` (already shipped; needs telemetry wiring) |
| #162 | Platform-specific integration tests | CI integration tests (plan 012) |
| #166 | Network Activity Table | Socket audit port (plan 013) |
| #167 | Quality Timeline | Journal data model (already shipped; needs UI) |
| #168 | Active Connections Audit | Socket audit port (plan 013) |
| #169 | WiFi/Network context in header | Net-info port (not planned; small surface) |
| #170 | One-key VPN speed test | Tunnel capability (small surface) |
| #171 | Session history timeline | Journal data model (already shipped; needs UI) |
| #172 | Network report export | Journal + serialization (small surface) |
| #177 | CLI hardening, typed errors, masking | Resolved by migration v1 (close on GA) |
| #190 | networkd / resolved DNS backend | DNS port (already shipped; needs second impl) |
| #191 | Interactive 2FA / MFA | FSM `AwaitingUserInput` (plan 008 U2 reservation) |
| #15 | Split tunneling configuration | RouteTable + new policy model (not planned; significant scope) |
| #31 | WG Connected with no handshake on invalid server | Resolved by migration v1 FSM (close on GA) |
| #164 | Update experience / What's New | Independent of arch; no plan needed |

## The 11 candidate gaps (output of the audit)

Audit was conducted by walking the codebase post-migration and
cross-referencing the open-issues backlog. Each candidate is rated for
**cost to retrofit** if left until the motivating feature lands.

### Track A — cheap-now (lands in PR #201, plan 008 executable)

| # | Gap | Cost now | Cost if deferred | Why land now |
|---|---|---|---|---|
| 1 | `--json` envelope `schema_version` | 30 min | High — every consumer breaks silently as fields evolve; semver-via-changelog is unenforceable | Establish the contract from day-one v0.3.0 |
| 2 | FSM `AwaitingUserInput` variant | 30 min | Medium — every TUI/CLI consumer adds a special case after 2FA ships | Variant + Input + Event added now; consumer wired by feature plan later |
| 3 | `Settings::schema_version` field | 20 min | Medium — when a settings field renames in v0.4, no detection path exists | Locks in a forward-migration story before the first schema change |
| 4 | `vortix-platform-windows` stub crate | 1–2 hr | High — until a Windows impl is attempted, every leak (cfg(unix), hardcoded /proc, etc.) hides | Forces Platform aggregate to admit a third OS; surfaces leaks free |
| 5 | Startup orphan-daemon scan | 45 min | High — silent gap, only surfaces when a user reports "vortix doesn't see my running tunnel" | Warn-only now; auto-adopt comes with plan 010 IPC |
| 6 | Cold-start perf test | 20 min | Medium — README claims <100ms; with no test, every PR can regress it | Locks in a numeric guarantee before features pile on |

### Track B — multi-week subsystems (plan docs land in PR #201, code lands in future PRs)

| # | Plan | Subsystem | Motivating issue | Why deferred |
|---|---|---|---|---|
| B1 | 009 | Lifecycle hooks | #36 | Real protocol design (event payloads, untrusted-script sandboxing, exec strategy) needs a session, not a sliver |
| B2 | 010 | IPC / `EngineHandle::Remote` | #16 (daemon mode) | Protocol choice (Unix socket vs gRPC vs JSON-RPC over stdin), serialization, auth model — all need a real plan |
| B3 | 011 | Privilege separation | #153 (run-without-sudo) | Fundamental redesign of subprocess model — root worker + unprivileged frontend, with IPC contract — depends on plan 010 |
| B4 | 012 | CI integration tests | #162 | Docker images for `wg`/`openvpn` matrix, GitHub Actions workflow, real-network test isolation — multi-week setup |
| B5 | 013 | Per-process socket-audit port | #168, #166 | Platform-specific (lsof on macOS, /proc/net/tcp on Linux, netstat-equivalent on Windows) — proper port + impls needs design |

## Decisions made during dialogue

1. **`schema_version` lands in v0.3.0, not v0.3.1.** Shipping it with
   the major release establishes the contract from day one; deferring
   to a patch would feel like an undeclared semver event.

2. **`AwaitingUserInput` is a top-level FSM variant, not a sub-state
   of `Connecting`.** Mid-flow user prompts are conceptually distinct
   from handshake negotiation; burying them inside `Connecting` would
   force every consumer to special-case two kinds of "Connecting."

3. **The Windows stub compiles on `cfg(target_os = "windows")` with
   always-errs `PlatformUnsupported` returns.** Proves the Platform
   aggregate admits a third OS while it's cheap; the alternative of
   skip-compile-on-Windows leaves platform leaks undetected until
   someone tries to build there.

4. **Plans 009–013 land as documents in PR #201 but are NOT
   executed.** Implementation happens in future PRs after v0.3.0 GA.
   Sequence: 009 → 010 → 011 → 012 → 013, ordered by external feature
   pressure and dependency.

5. **One-plan-per-PR going forward** — explicit lesson from PR #201's
   bundled-bundle stress. The 28-commit single PR worked but should
   not be the new norm.

## Assumptions (silent inferences, surfaced)

- v0.3.0 is the right cutover for new contracts like `schema_version`.
  Adding it in v0.3.1 would feel like an undeclared semver event.
- The 400-user base hasn't yet hit a daemon-mode use case at
  scale — no issue volume spike on #16 — so IPC waits for evidence,
  not just anticipation.
- The plan-008 through plan-013 series will be one-plan-per-PR going
  forward.
- No new architectural *code* lands before v0.3.0 GA except the six
  Track A items in PR #201 (plan 008). Track B plans are document-only
  in this PR.
- The audit is preemptive — the maintainer has felt no specific pain
  in the post-migration codebase. This biases the recommendation
  toward "cheap-now seams" over "speculative subsystems."

## Success criteria

For this brainstorm to have delivered value:

- [ ] Plan 008 (Track A) lands in PR #201 with all 6 units shipping
      green CI.
- [ ] Plans 009–013 land as document-only artifacts in PR #201, each
      with enough detail that a future implementer doesn't have to
      re-litigate the audit.
- [ ] No multi-week subsystem (Track B) ships code in PR #201 — the
      v0.3.0 rollout contract from plan 007 stays valid.
- [ ] When issue #16 (daemon mode), #36 (lifecycle hooks), or #153
      (run-without-sudo) is picked up by a contributor or the
      maintainer, the plan doc for 009/010/011 is the starting point,
      not a fresh brainstorm.
- [ ] When v0.4.0 needs to rename a Settings field, the
      `schema_version` mechanism from U3 is sufficient.

## Out of scope for THIS audit (but worth noting)

These came up during the dialogue but were judged either premature,
too-small-to-plan, or better handled elsewhere:

- **Versioning the on-disk journal JSONL format.** Already has
  `schema_version: u32` in `EventEnvelope` (per plan 005). Done.
- **Versioning the sidecar `.meta.toml` format.** Already has
  `Sidecar::SCHEMA_VERSION` (per plan 006). Done.
- **Replacing `eprintln!` with structured `tracing` calls
  systematically.** Worth doing but not architectural — file as an
  issue, not a plan.
- **A docs/architecture.md top-level reference.** Worth doing post-
  migration once the dust settles; not architectural debt.
- **Pinning MSRV in `rust-version.workspace`.** Already pinned (1.75
  per the README badge); no action needed.

## What happens next

1. Plan 008 is written and executed inside PR #201 (Track A items).
2. Plans 009–013 are written as document-only artifacts inside PR
   #201.
3. v0.3.0 ships via the playbook from plan 007.
4. Post-GA, when an upcoming feature pressure surfaces (or proactively
   at a calmer time), plans 009–013 are picked up one at a time in
   their own PRs.
