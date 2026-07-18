---
date: 2026-07-18
seq: 001
type: feat
slug: daemon-tunnel-ownership
status: active
depth: deep
origin: docs/brainstorms/2026-07-18-daemon-tunnel-ownership-requirements.md
issues: ["#234", "#250", "#153", "#16"]
supersedes: docs/plans/2026-05-24-010-feat-ipc-engine-handle-remote-plan.md
---

# Plan: Daemon as tunnel owner — phased completion arc

> **Resequence (2026-07-18, during execution):** U2 and U4 are merged. A
> real `RegistrySnapshot` over IPC (U2) requires the daemon to *own*
> registry state, which is exactly what the supervision migration (U4)
> provides — serving a snapshot the daemon doesn't hold is a placeholder,
> not the end-state. The merged phase (referred to below as **U2** — U4's
> unit body is retained for its test scenarios but its work folds into
> U2) makes the daemon host the `TunnelRegistry` + supervision loops,
> then exposes them over IPC. Delivered as a sequence of green commits
> within the single arc PR: (a) concurrent accept loop [done, `1c5289b`],
> (b) daemon hosts a registry structure, (c) supervisor loops re-homed
> from the TUI, (d) `RegistrySnapshot` served, (e) Subscribe streaming,
> (f) restart adoption, (g) TUI Remote cutover. Boot integration (U5),
> privilege hardening within U3, and closure (U6) are unchanged.

## Problem Frame

Every disruption-handling gap vortix has traces to one root: no long-lived process owns the tunnels. Supervision (drop detection, retry ladder, network monitor, kill-switch sync) runs only inside the TUI; the CLI is fire-and-forget; the kill switch is silently unenforced between reboot and next launch (#250); `sudo` is required for every mutation (#153). The daemon IPC skeleton shipped in v0.3.0 (UID-gated socket, framed protocol, Execute/Snapshot ops) but nothing operational routes through it — `EngineHandle` is `Local`-only, Subscribe is an ack stub, the snapshot is single-FSM, and the accept loop is serial.

Origin: `docs/brainstorms/2026-07-18-daemon-tunnel-ownership-requirements.md` (R1–R13, F1–F5, AE1–AE8). Prior art: `docs/plans/2026-05-24-010-feat-ipc-engine-handle-remote-plan.md` (superseded — treat as design notes, not a resumable plan).

---

## Scope

**In scope:** the full origin arc — Remote handle, registry-over-IPC + event streaming, CLI writes via daemon, supervision migration out of the TUI, boot integration (service install, persisted profiles, early-boot blocking unit), privilege separation via the UID gate, version-skew handshake, and the no-daemon fallback preserved bit-for-bit.

**Out of scope (from origin Scope Boundaries):** Windows; multi-user ACLs; auto-spawn-on-demand; per-tunnel OS units; new TUI panels beyond minimal discovery signals; network-exposed daemon API.

### Deferred to Follow-Up Work

- `app/update.rs` decomposition beyond what the supervision migration forces (the file is 1,558 lines; a broader split is its own refactor).
- Removing the client-side `flock` lifecycle lock — it stays as the no-daemon fallback's protection even after daemon arbitration lands.
- Prometheus/status-page consumers of the event stream (enabled by U2, not built here).

---

## Requirements Traceability

| Origin | Covered by |
|---|---|
| R1 (daemon owns registry) | U2, U3 |
| R2 (CLI writes via IPC) | U3 |
| R3 (TUI as client) | U4 |
| R4 (registry snapshot + events over IPC) | U2 |
| R5 (supervision loops in daemon) | U4 |
| R6 (arbitration) | U3 |
| R7 (tunnels survive daemon restart) | U4 |
| R8 (early-boot kill-switch) | U5 |
| R9 (boot-persisted profiles) | U5 |
| R10 (privilege separation) | U3 (gate + hardening), U6 (audit) |
| R11 (no-daemon fallback parity) | U1–U4 (each preserves Local path), verified in U6 |
| R12 (service install/uninstall) | U5 |
| R13 (version-skew detection) | U1 |

---

## Key Technical Decisions

- **Phases are PRs.** Each unit below is an independently mergeable PR that leaves main shippable. No phase depends on unmerged work. (Origin success criterion: ce-plan defines phase boundaries.)
- **Version handshake before anything else** (U1). Every subsequent phase changes the wire surface; skew detection (R13) must exist before the surface starts moving. Marker lives in the request/response envelope (a `Hello` exchange or per-frame version field — implementer picks the cheaper fit with the existing framing in `crates/vortix/src/vortix_core/ipc/`).
- **No-sudo arrives with CLI writes (U3), not at the end.** The shipped UID gate already authenticates the peer; routing writes through the root daemon makes passwordless operation fall out naturally. The same unit therefore carries the server-side input-hardening work (profile-name/path validation, command allow-listing) that plan 011 deferred — the boundary and its hardening ship together. (Confirmed in planning synthesis.)
- **TUI cutover is wholesale in U4** — when the daemon is present, the TUI's scanner/retry/netmon threads don't start; the Remote event stream is authoritative. No permanent dual-running cross-check. The Local path remains compiled and fully functional for the no-daemon case, which keeps drift-detection achievable by manual comparison when debugging. (Confirmed in planning synthesis.)
- **Concurrent accept loop is a prerequisite inside U2.** Event streaming means a TUI holds a long-lived connection while CLI commands arrive; the current one-client-at-a-time loop (`daemon/server.rs`) deadlocks that topology. Per-connection threads (matching the daemon's existing sync style) over an async rewrite — smallest change that unblocks streaming. (Confirmed in planning synthesis.)
- **Supervision moves by re-homing, not rewriting** (U4). The retry ladder (`state/retry.rs` + `HashMap<ProfileId, RetryState>` on `VpnRuntime`) and scanner cadence move into a daemon-side supervisor task that drives the engine directly instead of round-tripping through TUI `Message`s. The policy (backoff math, attempt caps, auth-failure awareness) is reused verbatim — AE3 pins it.
- **Daemon-restart adoption reuses the scanner** (R7). `scanner_adopt_session` and Method-0 log-based attribution already adopt externally-started tunnels; the daemon runs the same adoption at startup. Tunnels are never torn down by daemon exit (`Drop` stays no-op).
- **Early-boot unit is a static artifact, not daemon logic** (U5): a generated systemd unit (`Before=network-pre.target`) / launchd equivalent applying default-deny with DHCP/link-local carve-outs from the persisted kill-switch state file, replaced by the daemon's full ruleset when it starts. Mullvad-pattern.
- **WireGuard supervision is presence-only** (origin decision): the daemon's WG duty is interface presence + kill-switch coherence. Retry logic applies to OpenVPN; WG "drops" are interface-gone events, not handshake staleness.
- **CLI async bridging:** the CLI is synchronous; `RemoteHandle` is async (matching `EngineHandle`'s surface). The CLI blocks on the existing runner runtime (`vortix_process` tokio handle) — same pattern `build_engine_handle` uses today. No new runtime.

---

## High-Level Technical Design

*Directional guidance for review, not implementation specification.*

```
                     ┌──────────────────────────────────────────────┐
                     │ vortix daemon (root, boot-started, U5 unit)  │
                     │                                              │
   IPC (UDS, framed, │  EngineHandle::Local ── registry (truth)     │
   UID-gated,        │  supervisor task (U4):                       │
   versioned U1)     │    scanner tick → adopt/drop detect          │
        │            │    retry ladder (state/retry.rs policy)      │
        │            │    network monitor                           │
        │            │    kill-switch sync                          │
        ▼            │  IPC server (U2: concurrent, streaming)      │
┌───────────────┐    └──────────────────────────────────────────────┘
│ vortix (CLI)  │      ▲ Execute (U3: up/down/reconnect/killswitch)
│  Remote handle│──────┤ RegistrySnapshot (U2)
└───────────────┘      │ Subscribe → event frames (U2)
┌───────────────┐      │
│ vortix (TUI)  │──────┘  (U4: replaces in-process scanner/retry
│  Remote handle│          when socket present)
└───────────────┘
   │ no socket? → EngineHandle::Local + today's behavior (R11, every phase)

Boot (U5): [early-boot blocking unit: default-deny + DHCP/ND carve-outs]
        → [daemon starts: re-arms full ruleset, brings up persisted profiles]
```

---

## Phased Delivery

| Unit / PR | Ships | User-visible value when merged |
|---|---|---|
| U1 | Version handshake + `EngineHandle::Remote` (read) + `status` via Remote | Version-skew safety (AE8); ad-hoc status overlay replaced by the real seam |
| U2 | Registry snapshot + Subscribe streaming + concurrent server | `vortix status` shows full multi-tunnel state from the daemon; event stream exists for any client |
| U3 | CLI writes via daemon + arbitration + input hardening | **No more sudo** for daemon-installed users (AE1); cross-terminal races arbitrated centrally (AE7) |
| U4 | Supervision migration + TUI Remote cutover + restart adoption | **Headless reconnect** (AE2, AE3); tunnels survive daemon restart (AE4); TUI state continuity |
| U5 | `vortix service install/uninstall` + persisted profiles + early-boot unit | Boot persistence (#16), kill-switch reboot gap closed (#250, AE5) |
| U6 | Hardening audit + docs + backlog rows + fallback-parity verification | #234/#153 closed; AE6 verified; README/docs truthful |

---

## Implementation Units

### U1. Wire version handshake + `EngineHandle::Remote` (read path) + `vortix status` via Remote

**Goal:** The keystone seam. Add protocol versioning to the IPC layer, introduce the `Remote` variant implementing the read surface (`snapshot`), and replace `overlay_daemon_state` in the status path with the handle.

**Requirements:** R13, R11 (fallback preserved). Covers AE8.

**Dependencies:** none.

**Files:**
- `crates/vortix/src/vortix_core/ipc/` (version marker in envelope; new error variant for mismatch)
- `crates/vortix/src/vortix_core/engine/handle.rs` (add `Remote(RemoteHandle)` arm; method dispatch)
- `crates/vortix/src/daemon/client.rs` (evolve into the RemoteHandle transport: connection, request/response, version check)
- `crates/vortix/src/daemon/server.rs` (answer the version exchange)
- `crates/vortix/src/cli/commands.rs` (status path: construct Remote when socket present, drop `overlay_daemon_state`)
- Tests: `crates/vortix/src/daemon/` unit tests + a loopback client↔server integration test module

**Approach:** Keep the existing framed sync client as the transport core; wrap it in an async `RemoteHandle` bridged via the runner runtime for the CLI. Version mismatch is a typed error surfaced with both versions named — never a silent fallback (distinguish "socket absent" = silent Local fallback from "socket speaks wrong version" = loud error; the latter masks real bugs if silent).

**Patterns to follow:** `EngineHandle::local` construction and method dispatch (`handle.rs`); the framed request loop in `daemon/client.rs`; typed error style of `SocketAuditError`.

**Test scenarios:**
- Happy: loopback server + Remote snapshot returns the same `Connection` the Local handle reports.
- Covers AE8. Version mismatch: client with version N+1 marker against server N → typed mismatch error naming both; exit non-zero; no scanner fallback.
- Socket absent → status falls back to scanner path, output identical to today (golden compare).
- Socket present but connection drops mid-frame → clean error, no hang (read timeout).
- Malformed frame from server → `FrameError`, not panic.

**Verification:** `vortix status` output with and without a live daemon matches current behavior except sourced via the handle; version-mismatch integration test passes; no-daemon golden test passes.

---

### U2. Registry-over-IPC + concurrent accept loop + Subscribe streaming

**Goal:** The daemon serves full multi-tunnel state and pushes events; multiple clients connect simultaneously.

**Requirements:** R4, R1 (registry becomes the served truth). Enables F4.

**Dependencies:** U1.

**Files:**
- `crates/vortix/src/daemon/mod.rs` (daemon hosts the registry + engine per tunnel, not a single FSM)
- `crates/vortix/src/daemon/server.rs` (per-connection threads; `RegistrySnapshot` op implementation; `Subscribe` → long-lived push loop)
- `crates/vortix/src/vortix_core/ipc/` (registry snapshot + event frame types — `RegistrySnapshot` op is already reserved)
- `crates/vortix/src/vortix_core/engine/handle.rs` + `daemon/client.rs` (Remote: registry snapshot + subscribe stream consumption)
- Tests: loopback multi-client integration (one subscriber + one command client concurrently)

**Approach:** Per-connection thread with the UID gate run per accept (existing gate code reused). Subscribe holds the connection and writes event frames from a bounded broadcast buffer: state transitions are never dropped (coalesce to latest per tunnel under pressure); telemetry ticks may drop oldest. The journal's existing broadcast channel is the natural event source — verify at execution whether it carries enough (engine events) or the registry needs its own notify hook.

**Patterns to follow:** UID gate (`server.rs` peer-cred section); journal broadcast (`vortix_core/journal/`); bounded-channel patterns already in `vpn_runtime`.

**Test scenarios:**
- Two clients concurrently: subscriber receives events while a second client executes Snapshot — no serialization deadlock.
- Registry snapshot round-trips N tunnels with roles/health intact (serde equality).
- Slow subscriber: telemetry ticks drop, state transitions all arrive (order preserved per tunnel).
- Subscriber disconnect mid-stream → server thread exits cleanly, no fd leak (assert via repeated connect/disconnect loop).
- UID gate still rejects foreign-UID peers on every connection type (regression).

**Verification:** `vortix status` (via U1 path) now renders multi-tunnel state identical to the TUI's view of the same kernel state; multi-client integration tests pass; manual: TUI open + CLI status simultaneously against one daemon.

---

### U3. CLI writes via daemon + central arbitration + input hardening

**Goal:** `up`/`down`/`reconnect`/`killswitch` route through the daemon when present; the daemon arbitrates; passwordless CLI falls out via the UID gate — hardened.

**Requirements:** R2, R6, R1, R10 (boundary + hardening). Covers AE1, AE7; F1.

**Dependencies:** U2.

**Files:**
- `crates/vortix/src/cli/commands.rs` (handlers: Remote execute when socket present; Local path unchanged otherwise)
- `crates/vortix/src/daemon/server.rs` + `daemon/mod.rs` (Execute against the registry engine: conflict gate, connect/disconnect flows, kill-switch ops; per-command serialization inside the daemon)
- `crates/vortix/src/vortix_core/ipc/` (command + progress/result frames — connects are long-running; either stream progress over the same connection or return a command id polled via snapshot; pick at execution, progress-stream preferred to preserve CLI UX)
- Server-side validation module (profile name/path canonicalization, command allow-list — the plan-011 essentials)
- Tests: daemon-side arbitration units + CLI integration against loopback daemon

**Approach:** The daemon reuses the same connect machinery the CLI uses today (`vpn_runtime::connection` / engine inputs) but executes it in-daemon under a per-profile mutex; the CLI becomes a thin sender+renderer. Auth flows that need interactive input (OpenVPN OTP) remain client-side: client collects, sends with the command (the existing SCRV1 file-handoff path is replaced by in-band delivery for daemon mode — flag: credentials never logged, wipe after use). The client-side flock remains for the no-daemon path only.

**Test scenarios:**
- Covers AE7. Two concurrent `up` requests for one profile via IPC → one spawn, second gets already-connected/queued response.
- Covers AE1 (integration, gated to Linux CI where a loopback daemon can run as the test user): non-root client executes connect against the daemon-held engine mock; no privilege error.
- Validation: path traversal in profile name (`../../etc/passwd`), overlong names, non-catalog profiles → typed rejection, daemon logs, no execution.
- Conflict gate parity: DefaultRouteTakeover / RouteOverlap answers identical to today's CLI gate for the same registry state.
- Kill-switch ops round-trip and persist state file identically to the Local path.
- No-daemon: every handler's behavior byte-identical to today (golden tests on output).

**Verification:** With a daemon installed on the Linux droplet: `vortix up <profile>` as non-root connects; concurrent-terminal race test (the #249 scenario) now resolves via daemon arbitration; full no-daemon CLI test suite unchanged.

---

### U4. Supervision migration + TUI Remote cutover + restart adoption

**Goal:** The daemon supervises headlessly (scanner, retry ladder, netmon, kill-switch sync); the TUI becomes a subscriber when the daemon is present; daemon restart adopts running tunnels.

**Requirements:** R5, R3, R7. Covers AE2, AE3, AE4; F2, F4.

**Dependencies:** U2 (events), U3 (daemon executes reconnects).

**Files:**
- New daemon supervisor module (e.g., `crates/vortix/src/daemon/supervisor.rs`): scan cadence, drop detection, retry scheduling — driving engine inputs directly
- `crates/vortix/src/state/retry.rs` (policy reused; ladder driver re-homed out of `app/update.rs`)
- `crates/vortix/src/app/update.rs` + `app/telemetry_poll.rs` (gate the in-process scanner/retry/netmon behind "no daemon"; route daemon events into existing `Message` handling so render paths stay untouched)
- `crates/vortix/src/app/connection.rs` (TUI connect path → Remote execute when daemon present)
- `crates/vortix/src/daemon/mod.rs` (startup adoption via scanner before serving)
- Tests: supervisor unit tests with mock tunnels; TUI message-translation tests; adoption-on-start integration

**Approach:** Re-home, don't rewrite: the supervisor consumes the same scanner results and retry policy, but schedules via its own loop instead of TUI `Message`s. TUI translation layer maps subscribe events onto existing `Message` variants so `update.rs` render handling is minimally disturbed. Startup order in the daemon: adopt (scanner pass) → reconcile kill-switch → begin serving + supervising.

**Execution note:** Characterization-first for the retry ladder — capture today's TUI retry behavior (attempt counts, delays, auth-failure stop) in tests before moving the driver, so AE3 parity is proven, not assumed.

**Test scenarios:**
- Covers AE2. Mock tunnel killed externally → supervisor detects within one cadence, kill-switch input fired, reconnect scheduled with attempt=1.
- Covers AE3. Auth-failure result → retries stop at configured cap; state ends Failed, journaled.
- Covers AE4. Daemon restart with two mock-adopted sessions → both present in first snapshot, zero connect commands issued.
- User-initiated disconnect → no reconnect scheduled (auto_reconnect flag parity).
- TUI with daemon: no local scanner thread started (assert via runtime flag); events render identically to a scripted Local sequence.
- TUI without daemon: today's behavior (regression suite).

**Verification:** On the Linux droplet: connect via CLI, close everything, kill openvpn → tunnel returns within retry policy (AE2 live). Restart daemon mid-session → `wg show`/status unchanged (AE4 live). TUI attach shows continuity without rescan flicker.

---

### U5. Boot integration — service install, persisted profiles, early-boot blocking unit

**Goal:** `vortix service install/uninstall` manages the daemon unit + early-boot blocking unit; profiles can persist across boot; #250 and #16 close.

**Requirements:** R8, R9, R12. Covers AE5; F3.

**Dependencies:** U3 (daemon executes connects), U4 (supervision — boot-time bring-up needs it).

**Files:**
- New service-management module (e.g., `crates/vortix/src/cli/service.rs`): generate + install/uninstall systemd units / launchd plists (from `examples/systemd/vortix-daemon.service`, `examples/launchd/com.vortix.daemon.plist` as templates), plus the early-boot blocking unit
- `crates/vortix/src/vortix_platform_linux/firewall.rs` + macOS counterpart (emit the standalone early-boot ruleset from persisted kill-switch state: default-deny + DHCP/DHCPv6/ND/link-local carve-outs)
- Profile persistence marker (per-profile sidecar flag; daemon reads at startup)
- `crates/vortix/src/cli/args.rs` (new subcommand)
- Tests: unit-file generation goldens; carve-out ruleset tests; uninstall-leaves-nothing tests (tempdir-scoped)

**Approach:** Units are generated artifacts written to system locations only during explicit `service install` (root-checked); uninstall verifies removal of daemon unit, early-boot unit, and any armed rulesets (R12's no-zombie guarantee). Privilege elevation is plain `sudo` on both platforms (`sudo vortix service install`) — no macOS GUI authorization dialogs, preserving the works-over-SSH identity; a non-root invocation exits with the exact sudo command as the hint. Uninstall requires the same elevation and prints a verification summary of every artifact removed. Early-boot ordering (`Before=network-pre.target` exactness, launchd boot semantics) is flagged `[Needs research]` from the origin — resolve during execution with a real VM/droplet test per platform.

**Test scenarios:**
- Covers AE5 (manual + scripted on droplet): reboot with vpn-only + persisted profile → `curl` probes fail from earliest SSH-reachable moment until tunnel-up, DHCP renews fine.
- Generation goldens: unit/plist content for a given config (paths, user, ordering directives).
- Carve-outs: generated early-boot ruleset permits DHCP/ND, denies arbitrary egress (rule-content assertions, platform-gated).
- Uninstall: after install→uninstall cycle, no unit files, no enabled services, no persisted firewall artifacts remain.
- Persisted-profile flag round-trip; daemon startup brings up exactly the flagged set.

**Verification:** Full reboot test on the Ubuntu droplet (the #242 infra pattern): install service, persist profile, arm vpn-only, reboot, verify AE5's no-leak-window with timestamped probes; uninstall and verify clean state.

---

### U6. Hardening audit, docs, fallback parity, closure

**Goal:** Close the arc honestly: security review of the boundary, docs/README truthfulness, manual-testing rows, and verification that the no-daemon path never regressed.

**Requirements:** R10 (audit), R11 (parity verification). Covers AE6.

**Dependencies:** U1–U5.

**Files:**
- `README.md` (daemon section: capability ladder, install flow, updated kill-switch reboot note — replacing the #249-era caveat with the fixed story)
- `docs/manual-testing/backlog.md` (rows per phase: no-sudo flow, headless reconnect, daemon restart, reboot leak-window, uninstall cleanliness)
- `crates/vortix/CHANGELOG.md`
- Security review artifacts (run the repo's security-review flow over the daemon boundary; fix or file findings)
- Issue housekeeping: close #234/#250/#153/#16 with links; retire superseded plan-010 doc pointer

**Approach:** Covers AE6 with a scripted no-daemon parity suite (golden outputs across all CLI commands + TUI smoke without a socket). Discovery signal for missing supervision (R11's "discoverable") lands here as one status line — density principle: a signal, not a panel.

**Test scenarios:**
- Covers AE6. No-daemon golden suite across `up/down/status/reconnect/killswitch` — byte-parity with v0.4.x captured outputs (modulo version strings).
- Discovery line renders only when: daemon absent AND a state exists it would improve (e.g., killswitch armed or tunnel up).

**Verification:** Security review findings resolved or filed; all four issues closed with evidence links; CI green; manual rows executed on both platforms.

---

## System-Wide Impact

- **Two execution paths per surface** (Local/Remote) is the arc's standing cost — every future CLI/TUI feature must consider both. Mitigated by the `EngineHandle` seam keeping the branch in one place.
- **JSON envelope:** status output gains daemon-sourced fields; `schema_version` bump only if shapes change (avoid if possible — additive fields preferred).
- **Architectural boundaries:** daemon code lives in the binary crate (`daemon/`), consistent with today; `vortix_core` stays platform-free; xtask leak checks apply unchanged. The early-boot ruleset generation lives in platform crates.
- **Release/packaging:** no packaging changes until U5; then docs describe `service install` as post-install step — no installer-manager changes (Homebrew/cargo-dist untouched; the binary manages its own units).
- **#249's mitigations** (flock, orphan filter, pidfile guard) remain as the no-daemon fallback's protection — not removed.

---

## Risk Analysis & Mitigation

| Risk | Mitigation |
|---|---|
| U4 surgery in `app/update.rs` destabilizes TUI rendering | Event→`Message` translation layer keeps render handlers untouched; characterization tests on retry behavior before the move; no-daemon path exercises old wiring continuously |
| Long-running connect over IPC (U3) blocks the daemon or leaves half-connected state on client disconnect | Per-profile mutex + daemon-side completion independent of client connection (client disconnect ≠ cancel; explicit cancel op if needed — decide at execution) |
| Credential in-band delivery (U3, OTP flows) leaks via logs/journal | Explicit no-log guard tests; wipe-after-use; reuse PF-8 discipline from the SCRV1 work |
| Early-boot unit bricks networking on an edge distro (U5) | Carve-outs tested per-platform on droplets before release; `release-killswitch` escape documented; unit ships disabled unless vpn-only was armed |
| Version handshake breaks the one shipped consumer (status overlay) during U1 | U1 replaces that consumer in the same PR; backlog row 38 (V1-client vs V2-daemon) re-verified |
| Scope creep: daemon becomes mandatory in practice | AE6 golden-parity suite in CI (U6) makes fallback regressions loud |

---

## Success Metrics

- AE1–AE8 all pass (each mapped to a unit's tests/verification above).
- Issues #234, #250, #153, #16 closed by the arc; #249 mitigations demoted to fallback-only.
- No-daemon golden suite green in CI from U1 onward.

---

## Verification Plan (every unit)

Full CI parity set per `docs/ci-parity.md` (fmt, check, clippy workspace+all-targets, tests, rustdoc, xtask boundary checks) before each PR; live verification on the Ubuntu client droplet for U3–U5 (the #242/#249 test-infra pattern); macOS manual passes for install/uninstall (U5) and TUI cutover (U4).
